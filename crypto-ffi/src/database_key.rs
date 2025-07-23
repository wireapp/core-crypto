use core_crypto_keystore::{Connection as Database, ConnectionType};
#[cfg(target_family = "wasm")]
use wasm_bindgen::prelude::*;

use crate::{CoreCryptoError, CoreCryptoResult};

#[derive(Debug, derive_more::From, derive_more::Into, PartialEq, Eq)]
#[cfg_attr(target_family = "wasm", wasm_bindgen)]
#[cfg_attr(
    not(target_family = "wasm"),
    derive(Clone, derive_more::Deref, uniffi::Object),
    uniffi::export(Eq)
)]
pub struct DatabaseKey(core_crypto_keystore::DatabaseKey);

impl DatabaseKey {
    pub fn from_cc(cc: core_crypto_keystore::DatabaseKey) -> DatabaseKeyMaybeArc {
        #[cfg_attr(target_family = "wasm", expect(clippy::useless_conversion))]
        Self(cc).into()
    }
}

#[cfg(target_family = "wasm")]
#[wasm_bindgen]
impl DatabaseKey {
    #[wasm_bindgen(constructor)]
    pub fn new(buf: &[u8]) -> Result<DatabaseKey, wasm_bindgen::JsError> {
        let key = core_crypto_keystore::DatabaseKey::try_from(buf).map_err(CoreCryptoError::generic())?;
        Ok(DatabaseKey(key))
    }
}

#[cfg(not(target_family = "wasm"))]
#[uniffi::export]
impl DatabaseKey {
    #[uniffi::constructor]
    pub fn new(key: Vec<u8>) -> CoreCryptoResult<Self> {
        core_crypto_keystore::DatabaseKey::try_from(key.as_slice())
            .map(Self)
            .map_err(CoreCryptoError::generic())
    }
}

pub(crate) trait ToCc {
    fn to_cc(self) -> core_crypto_keystore::DatabaseKey;
}

#[cfg(target_family = "wasm")]
pub(crate) type DatabaseKeyMaybeArc = DatabaseKey;

#[cfg(target_family = "wasm")]
impl ToCc for DatabaseKeyMaybeArc {
    #[inline]
    fn to_cc(self) -> core_crypto_keystore::DatabaseKey {
        self.0
    }
}

#[cfg(not(target_family = "wasm"))]
pub(crate) type DatabaseKeyMaybeArc = std::sync::Arc<DatabaseKey>;

#[cfg(not(target_family = "wasm"))]
impl ToCc for DatabaseKeyMaybeArc {
    #[inline]
    fn to_cc(self) -> core_crypto_keystore::DatabaseKey {
        std::sync::Arc::unwrap_or_clone(self).0
    }
}

/// Updates the key of the CoreCrypto database.
/// To be used only once, when moving from CoreCrypto <= 5.x to CoreCrypto 6.x.
#[cfg_attr(target_family = "wasm", wasm_bindgen(js_name = "migrateDatabaseKeyTypeToBytes"))]
#[cfg_attr(not(target_family = "wasm"), uniffi::export)]
pub async fn migrate_db_key_type_to_bytes(name: &str, old_key: &str, new_key: &DatabaseKey) -> CoreCryptoResult<()> {
    Database::migrate_db_key_type_to_bytes(name, old_key, &new_key.0)
        .await
        .map_err(CoreCryptoError::generic())
}

/// Updates the key of the CoreCrypto database.
#[cfg_attr(target_family = "wasm", wasm_bindgen(js_name = "updateDatabaseKey"))]
#[cfg_attr(not(target_family = "wasm"), uniffi::export)]
pub async fn update_database_key(name: &str, old_key: &DatabaseKey, new_key: &DatabaseKey) -> CoreCryptoResult<()> {
    let mut db = Database::open(ConnectionType::Persistent(name), &old_key.0)
        .await
        .map_err(CoreCryptoError::generic())?;
    db.update_key(&new_key.0).await.map_err(CoreCryptoError::generic())?;
    db.close().await.map_err(CoreCryptoError::generic())?;
    Ok(())
}
