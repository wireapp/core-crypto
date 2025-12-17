use wasm_bindgen::JsValue;

use crate::{CryptoKeystoreResult, connection::platform::wasm::WasmStorageTransaction};

pub(crate) async fn delete_credential_by_session_id(
    transaction: &WasmStorageTransaction<'_>,
    session_id: Vec<u8>,
) -> CryptoKeystoreResult<()> {
    match transaction {
        WasmStorageTransaction::Persistent { tx: transaction, .. } => {
            let store = transaction.object_store("mls_credentials")?;
            let id = JsValue::from(session_id);
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
