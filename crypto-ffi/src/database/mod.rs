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
