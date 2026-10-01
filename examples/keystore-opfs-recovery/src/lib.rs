use core_crypto_keystore::connection::opfs_recovery_fixture;
use wasm_bindgen::prelude::*;

#[wasm_bindgen(jspi)]
pub async fn prepare(name: &str) -> Result<(), JsValue> {
    opfs_recovery_fixture::prepare(name)
        .await
        .map_err(|error| JsValue::from_str(&error))
}

#[wasm_bindgen(jspi)]
pub async fn recover(name: &str, fail_checkpoint: bool) -> Result<(), JsValue> {
    opfs_recovery_fixture::recover(name, fail_checkpoint)
        .await
        .map_err(|error| JsValue::from_str(&error))
}

#[wasm_bindgen(jspi)]
pub async fn finish() -> Result<(), JsValue> {
    opfs_recovery_fixture::finish()
        .await
        .map_err(|error| JsValue::from_str(&error))
}
