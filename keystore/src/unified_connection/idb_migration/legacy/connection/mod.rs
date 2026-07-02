pub(crate) mod platform;

use std::{
    borrow::Borrow,
    ops::{Deref, DerefMut},
    sync::Arc,
};

use async_lock::{Mutex, MutexGuard, Semaphore};
use async_trait::async_trait;

pub(crate) use self::platform::*;
use super::traits::{Entity, EntityDatabaseMutation, EntityDeleteBorrowed, EntityGetBorrowed, SearchableEntity};
use crate::{
    CryptoKeystoreError, CryptoKeystoreResult, DatabaseKey,
    entities::{MlsPendingMessage, PersistedMlsGroup},
    traits::{BorrowPrimaryKey, FetchFromDatabase, KeyType},
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
pub(crate) const MAX_BLOB_LEN: usize = 1_000_000_000;

#[cfg(not(target_os = "unknown"))]
// ? Because of UniFFI async requirements, we need our keystore to be Send as well now
pub(crate) trait DatabaseConnectionRequirements: Sized + Send {}
#[cfg(target_os = "unknown")]
// ? On the other hand, things cannot be Send on WASM because of platform restrictions (all things are copied across the
// FFI)
pub(crate) trait DatabaseConnectionRequirements: Sized {}

#[cfg_attr(target_os = "unknown", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_os = "unknown"), async_trait::async_trait)]
pub(crate) trait DatabaseConnection<'a>: DatabaseConnectionRequirements {
    type Connection: 'a;

    async fn open(location: &str, key: &DatabaseKey) -> CryptoKeystoreResult<Self>;

    async fn open_in_memory(key: &DatabaseKey) -> CryptoKeystoreResult<Self>;

    async fn update_key(&mut self, new_key: &DatabaseKey) -> CryptoKeystoreResult<()>;

    /// Clear all data from the database and close it.
    async fn wipe(self) -> CryptoKeystoreResult<()>;

    fn check_buffer_size(size: usize) -> CryptoKeystoreResult<()> {
        #[cfg(not(target_os = "unknown"))]
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

#[derive(Debug)]
pub(crate) struct Database {
    pub(crate) conn: Mutex<Option<KeystoreDatabaseConnection>>,
    pub(crate) transaction: Mutex<Option<KeystoreTransaction>>,
    // we need an internal Arc here so we can hand out `SemaphoreGuardArc`
    // instances without keeping references with lifetimes to the semaphore
    transaction_semaphore: Arc<Semaphore>,
}

const ALLOWED_CONCURRENT_TRANSACTIONS_COUNT: usize = 1;

// SAFETY: this has mutexes and atomics protecting underlying data so this is safe to share between threads
unsafe impl Send for Database {}
// SAFETY: this has mutexes and atomics protecting underlying data so this is safe to share between threads
unsafe impl Sync for Database {}

/// Where to open a connection
#[derive(Debug, Clone)]
pub(crate) enum ConnectionType<'a> {
    /// This connection is persistent at the provided path
    Persistent(&'a str),
    /// This connection is transient and lives in memory
    InMemory,
}

/// Exclusive access to the database connection
///
/// Note that this is only ever constructed when we already hold exclusive access,
/// and the connection has already been tested to ensure that it is non-empty.
pub(crate) struct ConnectionGuard<'a> {
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
    pub(crate) async fn open(location: ConnectionType<'_>, key: &DatabaseKey) -> CryptoKeystoreResult<Arc<Self>> {
        let conn = match location {
            ConnectionType::Persistent(location) => KeystoreDatabaseConnection::open(location, key).await?,
            ConnectionType::InMemory => KeystoreDatabaseConnection::open_in_memory(key).await?,
        };
        let conn = Mutex::new(Some(conn));
        Ok(Self {
            conn,
            transaction: Default::default(),
            transaction_semaphore: Arc::new(Semaphore::new(ALLOWED_CONCURRENT_TRANSACTIONS_COUNT)),
        }
        .into())
    }

    #[cfg(all(test, not(target_os = "unknown")))]
    pub(crate) async fn open_at_schema_version(
        name: &str,
        key: &DatabaseKey,
        version: MigrationTarget,
    ) -> CryptoKeystoreResult<Self> {
        let conn = KeystoreDatabaseConnection::init_with_key_at_schema_version(name, key, version)?;
        let conn = Mutex::new(Some(conn));
        Ok(Self {
            conn,
            transaction: Default::default(),
            transaction_semaphore: Arc::new(Semaphore::new(ALLOWED_CONCURRENT_TRANSACTIONS_COUNT)),
        })
    }

    #[cfg(all(test, target_os = "unknown"))]
    pub(crate) async fn open_at_schema_version(
        name: &str,
        key: &DatabaseKey,
        version: Option<u32>,
    ) -> CryptoKeystoreResult<Arc<Self>> {
        use crate::unified_connection::idb_migration::legacy::connection::{
            storage::{WasmEncryptedStorage, WasmStorageWrapper},
            wasm::migrations::{TARGET_VERSION, open_at},
        };

        let version = version.unwrap_or(TARGET_VERSION);
        let idb_database = open_at(name, key, version).await;
        let wasm_connection = KeystoreDatabaseConnection::from_inner(WasmEncryptedStorage::new(
            key,
            WasmStorageWrapper::Persistent(idb_database),
        ));
        let conn = Mutex::new(Some(wasm_connection));
        Ok(Self {
            conn,
            transaction: Default::default(),
            transaction_semaphore: Arc::new(Semaphore::new(ALLOWED_CONCURRENT_TRANSACTIONS_COUNT)),
        }
        .into())
    }

    pub(crate) async fn location(&self) -> CryptoKeystoreResult<Option<String>> {
        return Ok(self.conn().await?.location().map(ToString::to_string));
    }

    /// Get direct exclusive access to the connection.
    pub(crate) async fn conn(&self) -> CryptoKeystoreResult<ConnectionGuard<'_>> {
        self.conn.lock().await.try_into()
    }
}

// These and all other database impls shold not refer directly to `self.conn` but should go through the `self.conn()`
// wrapper
impl Database {
    /// Wait for any running transaction to finish, then take the connection out of this database,
    /// preventing this database from being used again.
    async fn take(&self) -> CryptoKeystoreResult<KeystoreDatabaseConnection> {
        let _semaphore = self.transaction_semaphore.acquire_arc().await;

        let mut guard = self.conn.lock().await;
        guard.take().ok_or(CryptoKeystoreError::Closed)
    }

    // Close this database connection
    pub(crate) async fn close(&self) -> CryptoKeystoreResult<()> {
        #[cfg(not(target_os = "unknown"))]
        self.take().await?;

        #[cfg(target_os = "unknown")]
        {
            let conn = self.take().await?;
            conn.close().await?;
        }
        Ok(())
    }

    /// Close this database and delete its contents.
    pub(crate) async fn wipe(&self) -> CryptoKeystoreResult<()> {
        self.take().await?.wipe().await
    }

    /// Export a copy of the database to the specified path.
    /// This creates a fully vacuumed and optimized copy of the database.
    /// The copy will be encrypted with the same key as the source database.
    ///
    /// # Platform Support
    /// This method is only available on platforms using SQLCipher (not WASM).
    ///
    /// # Arguments
    /// * `destination_path` - The file path where the database copy should be created
    ///
    /// # Errors
    /// Returns an error if:
    /// - The database is in-memory (cannot export in-memory databases)
    /// - The destination path is invalid
    /// - The export operation fails
    #[cfg(not(target_os = "unknown"))]
    pub(crate) async fn export_copy(&self, destination_path: &str) -> CryptoKeystoreResult<()> {
        let conn = self.conn().await?;
        conn.export_copy(destination_path).await
    }

    #[cfg(test)]
    pub(crate) async fn migrate_db_key_type_to_bytes(
        name: &str,
        old_key: &str,
        new_key: &DatabaseKey,
    ) -> CryptoKeystoreResult<()> {
        KeystoreDatabaseConnection::migrate_db_key_type_to_bytes(name, old_key, new_key).await
    }
}
