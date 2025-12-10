use std::{cell::RefCell, rc::Rc};

use js_sys::Uint8Array;
use wasm_bindgen::JsValue;

use super::{super::WasmConnection, InMemoryDB};
use crate::{CryptoKeystoreError, CryptoKeystoreResult, entities::Entity};

// The lifetime is to comply with the sqlite implementation.
pub enum WasmStorageTransaction<'a> {
    Persistent {
        tx: idb::Transaction,
        cipher: &'a aes_gcm::Aes256Gcm,
    },
    InMemory {
        db: Rc<RefCell<InMemoryDB>>,
        cipher: &'a aes_gcm::Aes256Gcm,
    },
}

impl WasmStorageTransaction<'_> {
    pub(crate) async fn commit_tx(self) -> CryptoKeystoreResult<()> {
        let Self::Persistent {
            tx: transaction,
            cipher: _cipher,
        } = self
        else {
            return Ok(());
        };
        let result = transaction.await?;
        if !result.is_committed() {
            return Err(CryptoKeystoreError::MlsKeyStoreError(
                "Transaction aborted. Check console logs for details.".to_string(),
            ));
        }
        Ok(())
    }

    pub(crate) async fn delete(&self, collection_name: &'static str, id: impl AsRef<[u8]>) -> CryptoKeystoreResult<()> {
        match self {
            WasmStorageTransaction::Persistent { tx, cipher: _cipher } => {
                let store = tx.object_store(collection_name)?;
                let k = Uint8Array::from(id.as_ref());
                store.delete(JsValue::from(k))?.await?;
            }
            WasmStorageTransaction::InMemory { db, cipher: _cipher } => {
                db.borrow_mut().entry(collection_name.into()).and_modify(|store| {
                    store.remove(id.as_ref());
                });
            }
        }
        Ok(())
    }

    pub(crate) async fn save<R: Entity<ConnectionType = WasmConnection>>(
        &self,
        mut entity: R,
    ) -> CryptoKeystoreResult<()> {
        let serializer = serde_wasm_bindgen::Serializer::json_compatible();
        let collection_name = R::COLLECTION_NAME;
        let key = entity.id()?;
        match self {
            WasmStorageTransaction::Persistent { tx, cipher } => {
                entity.encrypt(cipher)?;
                let js_value = entity.serialize(&serializer)?;
                let store = tx.object_store(collection_name)?;
                store.put(&js_value, Some(&key))?.await?;
            }
            WasmStorageTransaction::InMemory { db, cipher } => {
                entity.encrypt(cipher)?;
                let js_value = entity.serialize(&serializer)?;
                let mut map = db.borrow_mut();
                let entry = map.entry(collection_name.into()).or_default();
                let id = key
                    .as_string()
                    .map(|s| CryptoKeystoreResult::Ok(s.as_bytes().into()))
                    .unwrap_or_else(|| Ok(serde_wasm_bindgen::from_value(key)?))?;
                entry.insert(id, js_value);
            }
        }
        Ok(())
    }

    // This will start seeing use in WPB-22194
    #[expect(dead_code)]
    pub(crate) async fn count<E: Entity<ConnectionType = WasmConnection>>(&self) -> CryptoKeystoreResult<u32> {
        match self {
            WasmStorageTransaction::Persistent { tx, .. } => {
                let object_store = tx.object_store(E::COLLECTION_NAME)?;
                let count = object_store.count(None)?.await?;
                Ok(count)
            }
            WasmStorageTransaction::InMemory { db, .. } => {
                let map = db.borrow();
                Ok(map
                    .get(E::COLLECTION_NAME)
                    .map(|collection| collection.len())
                    .unwrap_or_default() as _)
            }
        }
    }
}
