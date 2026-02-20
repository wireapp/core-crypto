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
    pub async fn open(location: &str, key: Arc<DatabaseKey>) -> CoreCryptoResult<Self> {
        core_crypto_keystore::Database::open(core_crypto_keystore::ConnectionType::Persistent(location), key.as_ref())
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

#[uniffi::export]
impl Database {
    /// Get the location of the database
    /// Returns null if in-memory
    pub async fn get_location(&self) -> CoreCryptoResult<Option<String>> {
        self.location().await.map_err(CoreCryptoError::generic())
    }
}

/// Open or create a [Database].
#[uniffi::export]
pub async fn open_database(location: &str, key: Arc<DatabaseKey>) -> CoreCryptoResult<Database> {
    Database::open(location, key).await
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
/// This method is only useful on platforms using SQLCipher (iOS, Android, JVM, native).
/// On WASM platforms, this function will return an error.
///
/// # Arguments
/// * `database` - The database instance to export
/// * `destination_path` - The file path where the database copy should be created
//
// These feature flags are ugly, but here's how they work:
//
// - If the `wasm` feature is enabled, exlude this; we don't want it.
// - If we're compiling for wasm without the `wasm` feature, we have to have a function body, so just return an error
// - If we're compiling for non-wasm, we have the real impl
//
// This works out because we only ever build real wasm builds with the `wasm` feature flag enabled.
// The error could therefore be an `unimplemented!` but it's harmless to return a real error in this case.
#[cfg(not(feature = "wasm"))]
#[cfg_attr(all(not(feature = "wasm"), target_family = "wasm"), expect(unused_variables))]
#[uniffi::export]
pub async fn export_database_copy(database: &Database, destination_path: &str) -> CoreCryptoResult<()> {
    // we need a noop here for the case where we're compiling for wasm but without feature wasm
    #[cfg(target_family = "wasm")]
    {
        Err(CoreCryptoError::ad_hoc(
            "export_database_copy is not implemented for wasm",
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
