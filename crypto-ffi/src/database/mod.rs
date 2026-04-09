//! This module contains the `Database` struct acting as a core crypto keystore and the `DatabaseKey` used to open it.

mod key;

use std::sync::Arc;

pub use key::{DatabaseKey, migrate_database_key_type_to_bytes};

use crate::{CoreCryptoError, CoreCryptoResult};

/// The database acting as a core crypto keystore.
#[derive(Debug, derive_more::From, derive_more::Into, Clone, derive_more::Deref, uniffi::Object)]
pub struct Database(core_crypto_keystore::Database);

#[cfg(any(feature = "wasm", feature = "napi"))]
#[cfg_attr(any(feature = "wasm", feature = "napi"), uniffi::export)]
impl Database {
    /// Open or create a database.
    #[uniffi::constructor(name = "open")]
    pub async fn open(location: &str, key: Arc<DatabaseKey>) -> CoreCryptoResult<Self> {
        core_crypto_keystore::Database::open(core_crypto_keystore::ConnectionType::Persistent(location), key.as_ref())
            .await
            .map(Database)
            .map_err(CoreCryptoError::generic())
    }

    /// Create an in-memory database whose data will be lost when the instance is dropped.
    #[uniffi::constructor(name = "inMemory")]
    pub async fn in_memory(key: Arc<DatabaseKey>) -> CoreCryptoResult<Self> {
        core_crypto_keystore::Database::open(core_crypto_keystore::ConnectionType::InMemory, key.as_ref())
            .await
            .map(Database)
            .map_err(CoreCryptoError::generic())
    }
}

// Note: no uniffi::export, because static functions are not supported yet by uniffi version 0.29.
#[cfg(not(any(feature = "wasm", feature = "napi")))]
impl Database {
    /// Open or create a database.
    pub async fn open(location: &str, key: Arc<DatabaseKey>) -> CoreCryptoResult<Self> {
        core_crypto_keystore::Database::open(core_crypto_keystore::ConnectionType::Persistent(location), key.as_ref())
            .await
            .map(Database)
            .map_err(CoreCryptoError::generic())
    }

    /// Create an in-memory database whose data will be lost when the instance is dropped.
    pub async fn in_memory(key: Arc<DatabaseKey>) -> CoreCryptoResult<Self> {
        core_crypto_keystore::Database::open(core_crypto_keystore::ConnectionType::InMemory, key.as_ref())
            .await
            .map(Database)
            .map_err(CoreCryptoError::generic())
    }
}

#[uniffi::export]
impl Database {
    /// Get the location of the database.
    ///
    /// Returns null if the database is in-memory.
    pub async fn get_location(&self) -> CoreCryptoResult<Option<String>> {
        self.location().await.map_err(CoreCryptoError::generic())
    }

    /// Updates the key of the database.
    ///
    /// This reencrypts it with the new key.
    pub async fn update_key(&self, key: Arc<DatabaseKey>) -> CoreCryptoResult<()> {
        self.0.update_key(&key).await.map_err(CoreCryptoError::generic())
    }
}

#[cfg_attr(feature = "wasm", uniffi::export)]
impl Database {
    /// Close the database.
    ///
    /// Closing the database makes any `PkiEnvironment` and `CoreCrypto` instance created with it unusable.
    #[cfg(feature = "wasm")]
    pub async fn close(&self) -> CoreCryptoResult<()> {
        self.0.close().await.map_err(CoreCryptoError::generic())
    }
}

/// Open or create a database.
#[cfg(not(any(feature = "wasm", target_os = "unknown")))]
#[uniffi::export]
pub async fn open_database(location: &str, key: Arc<DatabaseKey>) -> CoreCryptoResult<Database> {
    Database::open(location, key).await
}

/// Create an in-memory database whose data will be lost when the instance is dropped.
#[cfg(not(any(feature = "wasm", target_os = "unknown")))]
#[uniffi::export]
pub async fn in_memory_database(key: Arc<DatabaseKey>) -> CoreCryptoResult<Database> {
    Database::in_memory(key).await
}

/// Export a fully vacuumed and optimized copy of the database to the specified path.
///
/// The copy is created using SQLite's VACUUM INTO command and is encrypted with the same key
/// as the source database. This is only available on platforms using SQLCipher
/// (iOS, Android, JVM, native).
//
// These feature flags are ugly, but here's how they work:
//
// - If the `wasm` feature is enabled or we're building for wasm, exlude this; we don't want it.
#[cfg(not(any(feature = "wasm", target_os = "unknown")))]
#[uniffi::export]
pub async fn export_database_copy(database: &Database, destination_path: &str) -> CoreCryptoResult<()> {
    // we need a noop here for the case where we're compiling for wasm but without feature wasm
    {
        database
            .0
            .export_copy(destination_path)
            .await
            .map_err(CoreCryptoError::generic())
    }
}
