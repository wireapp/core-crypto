//! This module contains the [Database] struct acting as a core crypto keystore and the [DatabaseKey] used to open it.

mod key;

#[cfg(target_family = "wasm")]
use wasm_bindgen::prelude::*;

use crate::{CoreCryptoError, CoreCryptoResult};

pub(super) use key::*;
pub use key::{DatabaseKey, migrate_database_key_type_to_bytes, update_database_key};

/// The database acting as a core crypto keystore.
#[derive(Debug, derive_more::From, derive_more::Into)]
#[cfg_attr(target_family = "wasm", wasm_bindgen)]
#[cfg_attr(not(target_family = "wasm"), derive(Clone, derive_more::Deref, uniffi::Object))]
pub struct Database(core_crypto_keystore::Database);

/// Open or create a [Database].
#[cfg_attr(not(target_family = "wasm"), uniffi::export)]
#[cfg_attr(target_family = "wasm", wasm_bindgen(js_name = openDatabase))]
pub async fn open_database(name: &str, key: DatabaseKeyMaybeArc) -> CoreCryptoResult<Database> {
    core_crypto_keystore::Database::open(core_crypto_keystore::ConnectionType::Persistent(name), &key.to_cc())
        .await
        .map(Database)
        .map_err(CoreCryptoError::generic())
}
