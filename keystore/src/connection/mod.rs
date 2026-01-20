use std::{borrow::Borrow, fmt, ops::Deref};

use async_trait::async_trait;
use sha2::{Digest as _, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop};

pub mod platform {
    cfg_if::cfg_if! {
        if #[cfg(target_family = "wasm")] {
            mod wasm;
            pub use self::wasm::WasmConnection as KeystoreDatabaseConnection;
            pub use wasm::storage;
            pub use self::wasm::storage::WasmStorageTransaction as TransactionWrapper;
        } else {
            mod generic;
            pub use self::generic::SqlCipherConnection as KeystoreDatabaseConnection;
            pub use self::generic::TransactionWrapper;
            #[cfg(test)]
            pub(crate) use generic::MigrationTarget;


        }
    }
}

use std::{ops::DerefMut, sync::Arc};

use async_lock::{Mutex, MutexGuard, Semaphore};

pub use self::platform::*;
use crate::{
    CryptoKeystoreError, CryptoKeystoreResult,
    entities::{MlsPendingMessage, PersistedMlsGroupExt},
    traits::{
        BorrowPrimaryKey, Entity, EntityDatabaseMutation, EntityDeleteBorrowed, EntityGetBorrowed, FetchFromDatabase,
        KeyType,
    },
    transaction::KeystoreTransaction,
};

/// Limit on the length of a blob to be stored in the database.
///
/// This limit applies to both SQLCipher-backed stores and WASM.
/// This limit is conservative on purpose when targeting WASM, as the lower bound that exists is Safari with a limit of
/// 1GB per origin.
///
/// See: [SQLite limits](https://www.sqlite.org/limits.html)
/// See: [IndexedDB limits](https://stackoverflow.com/a/63019999/1934177)
pub const MAX_BLOB_LEN: usize = 1_000_000_000;

#[cfg(not(target_family = "wasm"))]
// ? Because of UniFFI async requirements, we need our keystore to be Send as well now
pub trait DatabaseConnectionRequirements: Sized + Send {}
#[cfg(target_family = "wasm")]
// ? On the other hand, things cannot be Send on WASM because of platform restrictions (all things are copied across the
// FFI)
pub trait DatabaseConnectionRequirements: Sized {}

/// The key used to encrypt the database.
#[derive(Clone, Zeroize, ZeroizeOnDrop, derive_more::From, PartialEq, Eq)]
pub struct DatabaseKey([u8; Self::LEN]);

impl DatabaseKey {
    pub const LEN: usize = 32;

    pub fn generate() -> DatabaseKey {
        DatabaseKey(rand::random::<[u8; Self::LEN]>())
    }
}

impl fmt::Debug for DatabaseKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        f.write_str("DatabaseKey(hash=")?;
        for x in Sha256::digest(self).as_slice().iter().take(10) {
            fmt::LowerHex::fmt(x, f)?
        }
        f.write_str("...)")
    }
}

impl AsRef<[u8]> for DatabaseKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl Deref for DatabaseKey {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl TryFrom<&[u8]> for DatabaseKey {
    type Error = CryptoKeystoreError;

    fn try_from(buf: &[u8]) -> Result<Self, Self::Error> {
        if buf.len() != Self::LEN {
            Err(CryptoKeystoreError::InvalidDbKeySize {
                expected: Self::LEN,
                actual: buf.len(),
            })
        } else {
            Ok(Self(buf.try_into().unwrap()))
        }
    }
}

#[cfg_attr(target_family = "wasm", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_family = "wasm"), async_trait::async_trait)]
pub trait DatabaseConnection<'a>: DatabaseConnectionRequirements {
    type Connection: 'a;

    async fn open(location: &str, key: &DatabaseKey) -> CryptoKeystoreResult<Self>;

    async fn open_in_memory(key: &DatabaseKey) -> CryptoKeystoreResult<Self>;

    async fn update_key(&mut self, new_key: &DatabaseKey) -> CryptoKeystoreResult<()>;

    /// Clear all data from the database and close it.
    async fn wipe(self) -> CryptoKeystoreResult<()>;

    fn check_buffer_size(size: usize) -> CryptoKeystoreResult<()> {
        #[cfg(not(target_family = "wasm"))]
        if size > i32::MAX as usize {
            return Err(CryptoKeystoreError::BlobTooBig);
        }

        if size >= MAX_BLOB_LEN {
            return Err(CryptoKeystoreError::BlobTooBig);
        }

        Ok(())
    }

    /// Returns the database location if persistent or None if in-memory
    fn location(&self) -> Option<&str>;
}

#[derive(Debug, Clone)]
pub struct Database {
    pub(crate) conn: Arc<Mutex<Option<KeystoreDatabaseConnection>>>,
    pub(crate) transaction: Arc<Mutex<Option<KeystoreTransaction>>>,
    transaction_semaphore: Arc<Semaphore>,
}

const ALLOWED_CONCURRENT_TRANSACTIONS_COUNT: usize = 1;

/// Interface to fetch from the database either from the connection directly or through a
/// transaaction
#[cfg_attr(target_family = "wasm", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_family = "wasm"), async_trait::async_trait)]
pub trait OldFetchFromDatabase: Send + Sync {
    async fn find<E: Entity<ConnectionType = KeystoreDatabaseConnection>>(
        &self,
        id: impl AsRef<[u8]> + Send,
    ) -> CryptoKeystoreResult<Option<E>>;

    async fn find_unique<U: crate::entities::UniqueEntity<ConnectionType = KeystoreDatabaseConnection>>(
        &self,
    ) -> CryptoKeystoreResult<U>;

    async fn find_all<E: Entity<ConnectionType = KeystoreDatabaseConnection>>(
        &self,
        params: crate::entities::EntityFindParams,
    ) -> CryptoKeystoreResult<Vec<E>>;

    async fn find_many<E: Entity<ConnectionType = KeystoreDatabaseConnection>>(
        &self,
        ids: &[Vec<u8>],
    ) -> CryptoKeystoreResult<Vec<E>>;
    async fn count<E: Entity<ConnectionType = KeystoreDatabaseConnection>>(&self) -> CryptoKeystoreResult<usize>;
}

// SAFETY: this has mutexes and atomics protecting underlying data so this is safe to share between threads
unsafe impl Send for Database {}
// SAFETY: this has mutexes and atomics protecting underlying data so this is safe to share between threads
unsafe impl Sync for Database {}

/// Where to open a connection
#[derive(Debug, Clone)]
pub enum ConnectionType<'a> {
    /// This connection is persistent at the provided path
    Persistent(&'a str),
    /// This connection is transient and lives in memory
    InMemory,
}

/// Exclusive access to the database connection
///
/// Note that this is only ever constructed when we already hold exclusive access,
/// and the connection has already been tested to ensure that it is non-empty.
pub struct ConnectionGuard<'a> {
    guard: MutexGuard<'a, Option<KeystoreDatabaseConnection>>,
}

impl<'a> TryFrom<MutexGuard<'a, Option<KeystoreDatabaseConnection>>> for ConnectionGuard<'a> {
    type Error = CryptoKeystoreError;

    fn try_from(guard: MutexGuard<'a, Option<KeystoreDatabaseConnection>>) -> Result<Self, Self::Error> {
        guard
            .is_some()
            .then_some(Self { guard })
            .ok_or(CryptoKeystoreError::Closed)
    }
}

impl Deref for ConnectionGuard<'_> {
    type Target = KeystoreDatabaseConnection;

    fn deref(&self) -> &Self::Target {
        self.guard
            .as_ref()
            .expect("we have exclusive access and already checked that the connection exists")
    }
}

impl DerefMut for ConnectionGuard<'_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.guard
            .as_mut()
            .expect("we have exclusive access and already checked that the connection exists")
    }
}

// Only the functions in this impl block directly mess with `self.conn`
impl Database {
    pub async fn open(location: ConnectionType<'_>, key: &DatabaseKey) -> CryptoKeystoreResult<Self> {
        let conn = match location {
            ConnectionType::Persistent(location) => KeystoreDatabaseConnection::open(location, key).await?,
            ConnectionType::InMemory => KeystoreDatabaseConnection::open_in_memory(key).await?,
        };
        let conn = Mutex::new(Some(conn));
        #[allow(clippy::arc_with_non_send_sync)] // see https://github.com/rustwasm/wasm-bindgen/pull/955
        let conn = Arc::new(conn);
        Ok(Self {
            conn,
            transaction: Default::default(),
            transaction_semaphore: Arc::new(Semaphore::new(ALLOWED_CONCURRENT_TRANSACTIONS_COUNT)),
        })
    }

    #[cfg(all(test, not(target_family = "wasm")))]
    pub(crate) async fn open_at_schema_version(
        name: &str,
        key: &DatabaseKey,
        version: MigrationTarget,
    ) -> CryptoKeystoreResult<Self> {
        let conn = KeystoreDatabaseConnection::init_with_key_at_schema_version(name, key, version)?;
        let conn = Mutex::new(Some(conn));
        let conn = Arc::new(conn);
        Ok(Self {
            conn,
            transaction: Default::default(),
            transaction_semaphore: Arc::new(Semaphore::new(ALLOWED_CONCURRENT_TRANSACTIONS_COUNT)),
        })
    }

    pub async fn location(&self) -> CryptoKeystoreResult<Option<String>> {
        return Ok(self.conn().await?.location().map(ToString::to_string));
    }

    /// Get direct exclusive access to the connection.
    pub async fn conn(&self) -> CryptoKeystoreResult<ConnectionGuard<'_>> {
        self.conn.lock().await.try_into()
    }

    /// Wait for any running transaction to finish, then take the connection out of this database,
    /// preventing this database from being used again.
    async fn take(&self) -> CryptoKeystoreResult<KeystoreDatabaseConnection> {
        let _semaphore = self.transaction_semaphore.acquire_arc().await;

        let mut guard = self.conn.lock().await;
        guard.take().ok_or(CryptoKeystoreError::Closed)
    }

    // Close this database connection
    pub async fn close(&self) -> CryptoKeystoreResult<()> {
        #[cfg(not(target_family = "wasm"))]
        self.take().await?;

        #[cfg(target_family = "wasm")]
        {
            let conn = self.take().await?;
            conn.close().await?;
        }
        Ok(())
    }

    /// Close this database and delete its contents.
    pub async fn wipe(&self) -> CryptoKeystoreResult<()> {
        self.take().await?.wipe().await
    }

    pub async fn migrate_db_key_type_to_bytes(
        name: &str,
        old_key: &str,
        new_key: &DatabaseKey,
    ) -> CryptoKeystoreResult<()> {
        KeystoreDatabaseConnection::migrate_db_key_type_to_bytes(name, old_key, new_key).await
    }

    pub async fn update_key(&mut self, new_key: &DatabaseKey) -> CryptoKeystoreResult<()> {
        self.conn().await?.update_key(new_key).await
    }

    /// Waits for the current transaction to be committed or rolled back, then starts a new one.
    pub async fn new_transaction(&self) -> CryptoKeystoreResult<()> {
        let semaphore = self.transaction_semaphore.acquire_arc().await;
        let mut transaction_guard = self.transaction.lock().await;
        *transaction_guard = Some(KeystoreTransaction::new(semaphore).await?);
        Ok(())
    }

    pub async fn commit_transaction(&self) -> CryptoKeystoreResult<()> {
        let mut transaction_guard = self.transaction.lock().await;
        let Some(transaction) = transaction_guard.as_ref() else {
            return Err(CryptoKeystoreError::MutatingOperationWithoutTransaction);
        };
        transaction.commit(self).await?;
        *transaction_guard = None;
        Ok(())
    }

    pub async fn rollback_transaction(&self) -> CryptoKeystoreResult<()> {
        let mut transaction_guard = self.transaction.lock().await;
        if transaction_guard.is_none() {
            return Err(CryptoKeystoreError::MutatingOperationWithoutTransaction);
        };
        *transaction_guard = None;
        Ok(())
    }

    pub async fn child_groups<'a, E>(&self, entity: E) -> CryptoKeystoreResult<Vec<E>>
    where
        E: Clone + Entity + EntityDatabaseMutation<'a> + BorrowPrimaryKey + PersistedMlsGroupExt + Send + Sync,
        for<'pk> &'pk <E as BorrowPrimaryKey>::BorrowedPrimaryKey: KeyType,
    {
        let mut conn = self.conn().await?;
        let persisted_records = entity.child_groups(conn.deref_mut()).await?;

        let transaction_guard = self.transaction.lock().await;
        let Some(transaction) = transaction_guard.as_ref() else {
            return Ok(persisted_records);
        };
        transaction.child_groups(entity, persisted_records).await
    }

    pub async fn save<'a, E>(&self, entity: E) -> CryptoKeystoreResult<E::AutoGeneratedFields>
    where
        E: Entity + EntityDatabaseMutation<'a> + Send + Sync,
    {
        let transaction_guard = self.transaction.lock().await;
        let Some(transaction) = transaction_guard.as_ref() else {
            return Err(CryptoKeystoreError::MutatingOperationWithoutTransaction);
        };
        transaction.save(entity).await
    }

    pub async fn remove<'a, E>(&self, id: &E::PrimaryKey) -> CryptoKeystoreResult<()>
    where
        E: Entity + EntityDatabaseMutation<'a>,
    {
        let transaction_guard = self.transaction.lock().await;
        let Some(transaction) = transaction_guard.as_ref() else {
            return Err(CryptoKeystoreError::MutatingOperationWithoutTransaction);
        };
        transaction.remove::<E>(id).await
    }

    pub async fn remove_borrowed<'a, E>(&self, id: &E::BorrowedPrimaryKey) -> CryptoKeystoreResult<()>
    where
        E: Entity + EntityDatabaseMutation<'a> + BorrowPrimaryKey + EntityDeleteBorrowed<'a>,
    {
        let transaction_guard = self.transaction.lock().await;
        let Some(transaction) = transaction_guard.as_ref() else {
            return Err(CryptoKeystoreError::MutatingOperationWithoutTransaction);
        };
        transaction.remove_borrowed::<E>(id).await
    }

    pub async fn find_pending_messages_by_conversation_id(
        &self,
        conversation_id: &[u8],
    ) -> CryptoKeystoreResult<Vec<MlsPendingMessage>> {
        let mut conn = self.conn().await?;
        let persisted_records =
            MlsPendingMessage::find_all_by_conversation_id(&mut conn, conversation_id, Default::default()).await?;

        let transaction_guard = self.transaction.lock().await;
        let Some(transaction) = transaction_guard.as_ref() else {
            return Ok(persisted_records);
        };
        transaction
            .find_pending_messages_by_conversation_id(conversation_id, persisted_records)
            .await
    }

    pub async fn remove_pending_messages_by_conversation_id(
        &self,
        conversation_id: impl AsRef<[u8]> + Send,
    ) -> CryptoKeystoreResult<()> {
        let transaction_guard = self.transaction.lock().await;
        let Some(transaction) = transaction_guard.as_ref() else {
            return Err(CryptoKeystoreError::MutatingOperationWithoutTransaction);
        };
        transaction
            .remove_pending_messages_by_conversation_id(conversation_id)
            .await;
        Ok(())
    }
}

#[cfg_attr(target_family = "wasm", async_trait(?Send))]
#[cfg_attr(not(target_family = "wasm"), async_trait)]
impl FetchFromDatabase for Database {
    async fn get<E>(&self, id: &E::PrimaryKey) -> CryptoKeystoreResult<Option<E>>
    where
        E: Entity<ConnectionType = KeystoreDatabaseConnection> + Clone + Send + Sync,
    {
        // If a transaction is in progress...
        if let Some(transaction) = self.transaction.lock().await.as_ref()
            //... and it has information about this entity, ...
            && let Some(cached_record) = transaction.get(id).await
        {
            return Ok(cached_record.map(Arc::unwrap_or_clone));
        }

        // Otherwise get it from the database
        let mut conn = self.conn().await?;
        E::get(&mut conn, id).await
    }

    async fn get_borrowed<E>(&self, id: &<E as BorrowPrimaryKey>::BorrowedPrimaryKey) -> CryptoKeystoreResult<Option<E>>
    where
        E: EntityGetBorrowed<ConnectionType = KeystoreDatabaseConnection> + Clone + Send + Sync,
        E::PrimaryKey: Borrow<E::BorrowedPrimaryKey>,
        for<'a> &'a E::BorrowedPrimaryKey: KeyType,
    {
        // If a transaction is in progress...
        if let Some(transaction) = self.transaction.lock().await.as_ref()
            //... and it has information about this entity, ...
            && let Some(cached_record) = transaction.get_borrowed(id).await
        {
            return Ok(cached_record.map(Arc::unwrap_or_clone));
        }

        // Otherwise get it from the database
        let mut conn = self.conn().await?;
        E::get_borrowed(&mut conn, id).await
    }

    async fn count<E>(&self) -> CryptoKeystoreResult<u32>
    where
        E: Entity<ConnectionType = KeystoreDatabaseConnection> + Clone + Send + Sync,
    {
        if self.transaction.lock().await.is_some() {
            // Unfortunately, we have to do this because of possible record id overlap
            // between cache and db.
            let count = self.load_all::<E>().await?.len();
            Ok(count as _)
        } else {
            let mut conn = self.conn().await?;
            E::count(&mut conn).await
        }
    }

    async fn load_all<E>(&self) -> CryptoKeystoreResult<Vec<E>>
    where
        E: Entity<ConnectionType = KeystoreDatabaseConnection> + Clone + Send + Sync,
    {
        let mut conn = self.conn().await?;
        let persisted_records = E::load_all(&mut conn).await?;

        let transaction_guard = self.transaction.lock().await;
        let Some(transaction) = transaction_guard.as_ref() else {
            return Ok(persisted_records);
        };
        transaction.find_all(persisted_records).await
    }
}
