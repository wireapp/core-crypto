use core_crypto_keystore::{Connection as Database, ConnectionType};
#[cfg(target_family = "wasm")]
use wasm_bindgen::prelude::*;

use crate::{CoreCryptoError, CoreCryptoResult};

// TODO: We derive Constructor here only because we need to construct an instance in interop.
// Remove it once we drop the FFI client from interop.
#[derive(Debug, derive_more::From, derive_more::Into)]
#[cfg_attr(target_family = "wasm", wasm_bindgen)]
#[cfg_attr(not(target_family = "wasm"), derive(derive_more::Deref, derive_more::Constructor))]
pub struct DatabaseKey(core_crypto_keystore::DatabaseKey);

#[cfg(not(target_family = "wasm"))]
uniffi::custom_type!(DatabaseKey, Vec<u8>, {
    lower: |key| key.0.to_vec(),
    try_lift: |vec| {
        core_crypto_keystore::DatabaseKey::try_from(vec.as_slice())
            .map(DatabaseKey)
            .map_err(CoreCryptoError::generic())
            .map_err(Into::into)
    }
});

/// Updates the key of the CoreCrypto database.
/// To be used only once, when moving from CoreCrypto <= 5.x to CoreCrypto 6.x.
#[cfg_attr(target_family = "wasm", wasm_bindgen(js_name = "migrateDatabaseKeyTypeToBytes"))]
#[cfg_attr(not(target_family = "wasm"), uniffi::export)]
pub async fn migrate_db_key_type_to_bytes(name: &str, old_key: &str, new_key: &DatabaseKey) -> CoreCryptoResult<()> {
    Database::migrate_db_key_type_to_bytes(name, old_key, &new_key.0)
        .await
        .map_err(CoreCryptoError::generic())
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
