use std::fmt;
use std::ops::Deref;

use sha2::{Digest as _, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop};

pub mod platform {
    cfg_if::cfg_if! {
        if #[cfg(target_family = "wasm")] {
            mod wasm;
            pub use wasm::keystore_v_1_0_0;
            pub use self::wasm::WasmConnection as KeystoreDatabaseConnection;
            pub use wasm::storage;
            pub use self::wasm::storage::WasmStorageTransaction as TransactionWrapper;

            /// TODO: this is here only because it's needed for the cryptobox migration test.
            ///       Once we drop cryptobox migration and the related test, drop this too.
            pub use wasm::open_and_migrate_pre_v4;
        } else {
            mod generic;
            pub use self::generic::SqlCipherConnection as KeystoreDatabaseConnection;
            pub use self::generic::TransactionWrapper;
        }
    }
}

pub use self::platform::*;
use crate::entities::{Entity, EntityFindParams, StringEntityId};
use std::ops::DerefMut;

use crate::entities::{EntityTransactionExt, UniqueEntity};
use crate::transaction::KeystoreTransaction;
use crate::{CryptoKeystoreError, CryptoKeystoreResult};
use async_lock::{Mutex, MutexGuard, Semaphore};
use std::sync::Arc;

/// Limit on the length of a blob to be stored in the database.
///
/// This limit applies to both SQLCipher-backed stores and WASM.
/// This limit is conservative on purpose when targeting WASM, as the lower bound that exists is Safari with a limit of 1GB per origin.
///
/// See: [SQLite limits](https://www.sqlite.org/limits.html)
/// See: [IndexedDB limits](https://stackoverflow.com/a/63019999/1934177)
pub const MAX_BLOB_LEN: usize = 1_000_000_000;

#[cfg(not(target_family = "wasm"))]
// ? Because of UniFFI async requirements, we need our keystore to be Send as well now
pub trait DatabaseConnectionRequirements: Sized + Send {}
#[cfg(target_family = "wasm")]
// ? On the other hand, things cannot be Send on WASM because of platform restrictions (all things are copied across the FFI)
pub trait DatabaseConnectionRequirements: Sized {}

/// The key used to encrypt the database.
#[derive(Clone, Zeroize, ZeroizeOnDrop, derive_more::From)]
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

    async fn open(name: &str, key: &DatabaseKey) -> CryptoKeystoreResult<Self>;

    async fn open_in_memory(key: &DatabaseKey) -> CryptoKeystoreResult<Self>;

    async fn close(self) -> CryptoKeystoreResult<()>;

    /// Default implementation of wipe
    async fn wipe(self) -> CryptoKeystoreResult<()> {
        self.close().await
    }

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
}

#[derive(Debug, Clone)]
pub struct Connection {
    pub(crate) conn: Arc<Mutex<KeystoreDatabaseConnection>>,
    pub(crate) transaction: Arc<Mutex<Option<KeystoreTransaction>>>,
    transaction_semaphore: Arc<Semaphore>,
}

const ALLOWED_CONCURRENT_TRANSACTIONS_COUNT: usize = 1;

/// Interface to fetch from the database either from the connection directly or through a
/// transaaction
#[cfg_attr(target_family = "wasm", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_family = "wasm"), async_trait::async_trait)]
pub trait FetchFromDatabase: Send + Sync {
    async fn find<E: Entity<ConnectionType = KeystoreDatabaseConnection>>(
        &self,
        id: &[u8],
    ) -> CryptoKeystoreResult<Option<E>>;

    async fn find_unique<U: UniqueEntity<ConnectionType = KeystoreDatabaseConnection>>(
        &self,
    ) -> CryptoKeystoreResult<U>;

    async fn find_all<E: Entity<ConnectionType = KeystoreDatabaseConnection>>(
        &self,
        params: EntityFindParams,
    ) -> CryptoKeystoreResult<Vec<E>>;

    async fn find_many<E: Entity<ConnectionType = KeystoreDatabaseConnection>>(
        &self,
        ids: &[Vec<u8>],
    ) -> CryptoKeystoreResult<Vec<E>>;
    async fn count<E: Entity<ConnectionType = KeystoreDatabaseConnection>>(&self) -> CryptoKeystoreResult<usize>;
}

// SAFETY: this has mutexes and atomics protecting underlying data so this is safe to share between threads
unsafe impl Send for Connection {}
// SAFETY: this has mutexes and atomics protecting underlying data so this is safe to share between threads
unsafe impl Sync for Connection {}

/// Where to open a connection
#[derive(Debug, Clone)]
pub enum ConnectionType<'a> {
    /// This connection is persistent at the provided path
    Persistent(&'a str),
    /// This connection is transient and lives in memory
    InMemory,
}

impl Connection {
    pub async fn open(location: ConnectionType<'_>, key: &DatabaseKey) -> CryptoKeystoreResult<Self> {
        let conn = match location {
            ConnectionType::Persistent(name) => KeystoreDatabaseConnection::open(name, key).await?.into(),
            ConnectionType::InMemory => KeystoreDatabaseConnection::open_in_memory(key).await?.into(),
        };
        #[allow(clippy::arc_with_non_send_sync)] // see https://github.com/rustwasm/wasm-bindgen/pull/955
        let conn = Arc::new(conn);
        Ok(Self {
            conn,
            transaction: Default::default(),
            transaction_semaphore: Arc::new(Semaphore::new(ALLOWED_CONCURRENT_TRANSACTIONS_COUNT)),
        })
    }

    pub async fn borrow_conn(&self) -> CryptoKeystoreResult<MutexGuard<'_, KeystoreDatabaseConnection>> {
        Ok(self.conn.lock().await)
    }

    pub async fn migrate_db_key_type_to_bytes(
        name: &str,
        old_key: &str,
        new_key: &DatabaseKey,
    ) -> CryptoKeystoreResult<()> {
        KeystoreDatabaseConnection::migrate_db_key_type_to_bytes(name, old_key, new_key).await
    }

    pub async fn wipe(self) -> CryptoKeystoreResult<()> {
        if self.transaction.lock().await.is_some() {
            return Err(CryptoKeystoreError::TransactionInProgress {
                attempted_operation: "wipe()".to_string(),
            });
        }
        let conn: KeystoreDatabaseConnection = Arc::into_inner(self.conn).unwrap().into_inner();
        conn.wipe().await?;
        Ok(())
    }

    pub async fn can_close(&self) -> bool {
        // transaction in progress
        if self.transaction.lock().await.is_some() {
            return false;
        }
        Arc::strong_count(&self.conn) <= 1
    }

    pub async fn close(self) -> CryptoKeystoreResult<()> {
        if self.transaction.lock().await.is_some() {
            return Err(CryptoKeystoreError::TransactionInProgress {
                attempted_operation: "close()".to_string(),
            });
        }
        let Some(conn) = Arc::into_inner(self.conn) else {
            return Err(CryptoKeystoreError::CannotClose);
        };
        let conn = conn.into_inner();
        conn.close().await?;
        Ok(())
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

    pub async fn child_groups<
        E: Entity<ConnectionType = KeystoreDatabaseConnection> + crate::entities::PersistedMlsGroupExt + Sync,
    >(
        &self,
        entity: E,
    ) -> CryptoKeystoreResult<Vec<E>> {
        let mut conn = self.conn.lock().await;
        let persisted_records = entity.child_groups(conn.deref_mut()).await?;

        let transaction_guard = self.transaction.lock().await;
        let Some(transaction) = transaction_guard.as_ref() else {
            return Ok(persisted_records);
        };
        transaction.child_groups(entity, persisted_records).await
    }

    pub async fn save<E: Entity<ConnectionType = KeystoreDatabaseConnection> + Sync + EntityTransactionExt>(
        &self,
        entity: E,
    ) -> CryptoKeystoreResult<E> {
        let transaction_guard = self.transaction.lock().await;
        let Some(transaction) = transaction_guard.as_ref() else {
            return Err(CryptoKeystoreError::MutatingOperationWithoutTransaction);
        };
        transaction.save_mut(entity).await
    }

    pub async fn remove<
        E: Entity<ConnectionType = KeystoreDatabaseConnection> + EntityTransactionExt,
        S: AsRef<[u8]>,
    >(
        &self,
        id: S,
    ) -> CryptoKeystoreResult<()> {
        let transaction_guard = self.transaction.lock().await;
        let Some(transaction) = transaction_guard.as_ref() else {
            return Err(CryptoKeystoreError::MutatingOperationWithoutTransaction);
        };
        transaction.remove::<E, S>(id).await
    }

    pub async fn cred_delete_by_credential(&self, cred: Vec<u8>) -> CryptoKeystoreResult<()> {
        let transaction_guard = self.transaction.lock().await;
        let Some(transaction) = transaction_guard.as_ref() else {
            return Err(CryptoKeystoreError::MutatingOperationWithoutTransaction);
        };
        transaction.cred_delete_by_credential(cred).await
    }
}

#[cfg_attr(target_family = "wasm", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_family = "wasm"), async_trait::async_trait)]
impl FetchFromDatabase for Connection {
    async fn find<E: Entity<ConnectionType = KeystoreDatabaseConnection>>(
        &self,
        id: &[u8],
    ) -> CryptoKeystoreResult<Option<E>> {
        // If a transaction is in progress...
        if let Some(transaction) = self.transaction.lock().await.as_ref() {
            //... and it has information about this entity, ...
            if let Some(result) = transaction.find::<E>(id).await? {
                // ... return that result
                return Ok(result);
            }
        }

        // Otherwise get it from the database
        let mut conn = self.conn.lock().await;
        E::find_one(&mut conn, &id.into()).await
    }

    async fn find_unique<U: UniqueEntity>(&self) -> CryptoKeystoreResult<U> {
        // If a transaction is in progress...
        if let Some(transaction) = self.transaction.lock().await.as_ref() {
            //... and it has information about this entity, ...
            if let Some(result) = transaction.find_unique::<U>().await? {
                // ... return that result
                return Ok(result);
            }
        }
        // Otherwise get it from the database
        let mut conn = self.conn.lock().await;
        U::find_unique(&mut conn).await
    }

    async fn find_all<E: Entity<ConnectionType = KeystoreDatabaseConnection>>(
        &self,
        params: EntityFindParams,
    ) -> CryptoKeystoreResult<Vec<E>> {
        let mut conn = self.conn.lock().await;
        let persisted_records = E::find_all(&mut conn, params.clone()).await?;

        let transaction_guard = self.transaction.lock().await;
        let Some(transaction) = transaction_guard.as_ref() else {
            return Ok(persisted_records);
        };
        transaction.find_all(persisted_records, params).await
    }

    async fn find_many<E: Entity<ConnectionType = KeystoreDatabaseConnection>>(
        &self,
        ids: &[Vec<u8>],
    ) -> CryptoKeystoreResult<Vec<E>> {
        let entity_ids: Vec<StringEntityId> = ids.iter().map(|id| id.as_slice().into()).collect();
        let mut conn = self.conn.lock().await;
        let persisted_records = E::find_many(&mut conn, &entity_ids).await?;

        let transaction_guard = self.transaction.lock().await;
        let Some(transaction) = transaction_guard.as_ref() else {
            return Ok(persisted_records);
        };
        transaction.find_many(persisted_records, ids).await
    }

    async fn count<E: Entity<ConnectionType = KeystoreDatabaseConnection>>(&self) -> CryptoKeystoreResult<usize> {
        if self.transaction.lock().await.is_some() {
            // Unfortunately, we have to do this because of possible record id overlap
            // between cache and db.
            return Ok(self.find_all::<E>(Default::default()).await?.len());
        };
        let mut conn = self.conn.lock().await;
        E::count(&mut conn).await
    }
}
