use wasm_bindgen::JsValue;

use crate::{
    CryptoKeystoreError, CryptoKeystoreResult, connection::platform::wasm::WasmStorageTransaction,
    entities::Entity as _, migrations::V5Credential,
};

pub(crate) async fn delete_credential_by_value(
    transaction: &WasmStorageTransaction<'_>,
    credential: Vec<u8>,
) -> CryptoKeystoreResult<()> {
    match transaction {
        WasmStorageTransaction::Persistent {
            tx: transaction,
            cipher,
        } => {
            let store = transaction.object_store("mls_credentials")?;
            let store_index = store.index("credential")?;
            let credential_js: wasm_bindgen::JsValue = js_sys::Uint8Array::from(&credential[..]).into();
            let request = store_index.get(credential_js)?;
            let Some(entity_raw) = request.await? else {
                let reason = "'credential' in 'mls_credentials' collection";
                let value = hex::encode(&credential);
                return Err(CryptoKeystoreError::NotFound(reason, value));
            };

            let mut credential = serde_wasm_bindgen::from_value::<V5Credential>(entity_raw)?;
            credential.decrypt(cipher)?;

            let id = JsValue::from(credential.id.clone());
            let request = store.delete(id)?;
            request.await?;
        }
        WasmStorageTransaction::InMemory { .. } => {
            // current table model does not fit in a hashmap (no more primary key)
            // memory keystore is never used in prod
        }
    }

    Ok(())
}
