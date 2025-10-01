//! This module contains the [Database] struct acting as a core crypto keystore and the [DatabaseKey] used to open it.

mod key;

#[cfg(target_family = "wasm")]
use wasm_bindgen::prelude::*;

use crate::{CoreCryptoError, CoreCryptoResult};

pub(super) use key::*;
pub use key::{DatabaseKey, migrate_database_key_type_to_bytes, update_database_key};

pub(crate) trait ToCc {
    type Target;

    fn to_cc(self) -> Self::Target;
}

/// The database acting as a core crypto keystore.
#[derive(Debug, derive_more::From, derive_more::Into)]
#[cfg_attr(target_family = "wasm", wasm_bindgen)]
#[cfg_attr(not(target_family = "wasm"), derive(Clone, derive_more::Deref, uniffi::Object))]
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
#[cfg_attr(not(target_family = "wasm"), uniffi::export)]
#[cfg_attr(target_family = "wasm", wasm_bindgen(js_name = openDatabase))]
pub async fn open_database(name: &str, key: DatabaseKeyMaybeArc) -> CoreCryptoResult<Database> {
    Database::open(name, key).await
}

/// Create an in-memory [Database] whose data will be lost when the instance is dropped.
#[cfg_attr(not(target_family = "wasm"), uniffi::export)]
#[cfg_attr(target_family = "wasm", wasm_bindgen(js_name = inMemoryDatabase))]
pub async fn in_memory_database(key: DatabaseKeyMaybeArc) -> CoreCryptoResult<Database> {
    Database::in_memory(key).await
}

#[cfg(target_family = "wasm")]
pub(crate) type DatabaseMaybeArc = Database;

/// This needs to be wrapped in an arc for uniffi to allow this as a parameter for exported functions.
#[cfg(not(target_family = "wasm"))]
pub(crate) type DatabaseMaybeArc = std::sync::Arc<Database>;

impl ToCc for DatabaseMaybeArc {
    type Target = core_crypto_keystore::Database;

    fn to_cc(self) -> Self::Target {
        #[cfg(not(target_family = "wasm"))]
        let target = std::sync::Arc::unwrap_or_clone(self).0;

        #[cfg(target_family = "wasm")]
        let target = self.0;

        target
    }
}
