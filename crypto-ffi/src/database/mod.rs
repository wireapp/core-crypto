//! This module contains the [Database] struct acting as a core crypto keystore and the [DatabaseKey] used to open it.

mod key;

pub(super) use key::*;
pub use key::{DatabaseKey, migrate_database_key_type_to_bytes, update_database_key};

use crate::{CoreCryptoError, CoreCryptoResult};

pub(crate) trait ToCc {
    type Target;

    fn to_cc(self) -> Self::Target;
}

/// The database acting as a core crypto keystore.
#[derive(Debug, derive_more::From, derive_more::Into, Clone, derive_more::Deref, uniffi::Object)]
pub struct Database(core_crypto_keystore::Database);

impl Database {
    /// Open or create a [Database].
    pub async fn open(name: &str, key: DatabaseKeyMaybeArc) -> CoreCryptoResult<Self> {
        core_crypto_keystore::Database::open(core_crypto_keystore::ConnectionType::Persistent(name), &key.to_cc())
            .await
            .map(Database)
            .map_err(CoreCryptoError::generic())
    }

    /// Create an in-memory [Database] whose data will be lost when the instance is dropped.
    pub async fn in_memory(key: DatabaseKeyMaybeArc) -> CoreCryptoResult<Self> {
        core_crypto_keystore::Database::open(core_crypto_keystore::ConnectionType::InMemory, &key.to_cc())
            .await
            .map(Database)
            .map_err(CoreCryptoError::generic())
    }
}

/// Open or create a [Database].
#[uniffi::export]
pub async fn open_database(name: &str, key: DatabaseKeyMaybeArc) -> CoreCryptoResult<Database> {
    Database::open(name, key).await
}

/// Create an in-memory [Database] whose data will be lost when the instance is dropped.
#[uniffi::export]
pub async fn in_memory_database(key: DatabaseKeyMaybeArc) -> CoreCryptoResult<Database> {
    Database::in_memory(key).await
}

/// This needs to be wrapped in an arc for uniffi to allow this as a parameter for exported functions.
pub(crate) type DatabaseMaybeArc = std::sync::Arc<Database>;

impl ToCc for DatabaseMaybeArc {
    type Target = core_crypto_keystore::Database;

    fn to_cc(self) -> Self::Target {
        std::sync::Arc::unwrap_or_clone(self).0
    }
}
