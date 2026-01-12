//! This module contains the [Database] struct acting as a core crypto keystore and the [DatabaseKey] used to open it.

mod key;

use std::sync::Arc;

pub use key::{DatabaseKey, migrate_database_key_type_to_bytes, update_database_key};

use crate::{CoreCryptoError, CoreCryptoResult};

/// The database acting as a core crypto keystore.
#[derive(Debug, derive_more::From, derive_more::Into, Clone, derive_more::Deref, uniffi::Object)]
pub struct Database(core_crypto_keystore::Database);

impl Database {
    /// Open or create a [Database].
    pub async fn open(name: &str, key: Arc<DatabaseKey>) -> CoreCryptoResult<Self> {
        core_crypto_keystore::Database::open(core_crypto_keystore::ConnectionType::Persistent(name), key.as_ref())
            .await
            .map(Database)
            .map_err(CoreCryptoError::generic())
    }

    /// Create an in-memory [Database] whose data will be lost when the instance is dropped.
    pub async fn in_memory(key: Arc<DatabaseKey>) -> CoreCryptoResult<Self> {
        core_crypto_keystore::Database::open(core_crypto_keystore::ConnectionType::InMemory, key.as_ref())
            .await
            .map(Database)
            .map_err(CoreCryptoError::generic())
    }
}

/// Open or create a [Database].
#[uniffi::export]
pub async fn open_database(name: &str, key: Arc<DatabaseKey>) -> CoreCryptoResult<Database> {
    Database::open(name, key).await
}

/// Create an in-memory [Database] whose data will be lost when the instance is dropped.
#[uniffi::export]
pub async fn in_memory_database(key: Arc<DatabaseKey>) -> CoreCryptoResult<Database> {
    Database::in_memory(key).await
}

/// Export a copy of the database to the specified path.
///
/// This creates a fully vacuumed and optimized copy of the database using SQLite's VACUUM INTO command.
/// The copy will be encrypted with the same key as the source database.
///
/// # Platform Support
/// This method is only available on platforms using SQLCipher (iOS, Android, JVM, native).
/// On WASM platforms, this function will return an error.
///
/// # Arguments
/// * `database` - The database instance to export
/// * `destination_path` - The file path where the database copy should be created
///
/// # Errors
/// Returns an error if:
/// - Called on WASM platform (not supported)
/// - The database is in-memory (cannot export in-memory databases)
/// - The destination path is invalid or not writable
/// - The export operation fails
#[uniffi::export]
pub async fn export_database_copy(database: &Database, destination_path: &str) -> CoreCryptoResult<()> {
    #[cfg(target_family = "wasm")]
    {
        let _ = (database, destination_path); // Suppress unused warnings
        Err(CoreCryptoError::ad_hoc(
            "export_database_copy is not supported on WASM. This function requires filesystem operations and SQLCipher, which are only available on native platforms (iOS, Android, JVM).",
        ))
    }

    #[cfg(not(target_family = "wasm"))]
    {
        database
            .0
            .export_copy(destination_path)
            .await
            .map_err(CoreCryptoError::generic())
    }
}
