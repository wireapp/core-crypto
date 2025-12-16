use std::{cell::RefCell, rc::Rc};

use js_sys::Uint8Array;
use serde::Serialize;
use wasm_bindgen::JsValue;

use super::{super::WasmConnection, InMemoryDB};
use crate::{
    CryptoKeystoreError, CryptoKeystoreResult,
    entities::Entity,
    traits::{Encrypting, Entity as NewEntity, KeyType},
};

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
    fn cipher(&self) -> &aes_gcm::Aes256Gcm {
        match self {
            WasmStorageTransaction::Persistent { cipher, .. } => cipher,
            WasmStorageTransaction::InMemory { cipher, .. } => cipher,
        }
    }

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

    /// Count the number of entities in this transaction.
    pub(crate) async fn new_count<E>(&self) -> CryptoKeystoreResult<u32>
    where
        E: NewEntity<ConnectionType = WasmConnection>,
    {
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

    /// Save an entity instance into the transaction.
    pub(crate) async fn new_save<'a, E>(&self, entity: &'a E) -> CryptoKeystoreResult<()>
    where
        E: NewEntity<ConnectionType = WasmConnection> + Encrypting<'a>,
    {
        let serializer = serde_wasm_bindgen::Serializer::json_compatible();
        let encrypted = entity.encrypt(self.cipher())?;
        let js_value = encrypted.serialize(&serializer)?;

        let key = JsValue::from(Uint8Array::from(entity.primary_key().bytes().as_ref()));

        match self {
            WasmStorageTransaction::Persistent { tx, .. } => {
                let store = tx.object_store(E::COLLECTION_NAME)?;
                store.put(&js_value, Some(&key))?.await?;
            }
            WasmStorageTransaction::InMemory { db, .. } => {
                let mut map = db.borrow_mut();
                let entry = map.entry(E::COLLECTION_NAME.into()).or_default();
                let id = key
                    .as_string()
                    .map(|s| CryptoKeystoreResult::Ok(s.as_bytes().into()))
                    .unwrap_or_else(|| Ok(serde_wasm_bindgen::from_value(key)?))?;
                entry.insert(id, js_value);
            }
        }

        Ok(())
    }

    /// Remove an entity by key from the transaction.
    ///
    /// Note that `key`'s type is not directly tied to `E`. We don't know if `E` implements
    /// `BorrowPrimaryKey` or not, and without specialization, we can't just do the right thing
    /// and accept the more general form. But we do know the primary key and its borrowed form
    /// both implement `KeyType`, so it's always safe to accept a byte reference.
    pub(crate) async fn new_delete<E>(&self, key: &[u8]) -> CryptoKeystoreResult<bool>
    where
        E: NewEntity<ConnectionType = WasmConnection>,
    {
        match self {
            WasmStorageTransaction::Persistent { tx, .. } => {
                let query = JsValue::from(Uint8Array::from(key));

                let store = tx.object_store(E::COLLECTION_NAME)?;
                let existed = store.count(Some(query.clone().into()))?.await?;
                store.delete(query)?.await?;

                Ok(existed > 0)
            }
            WasmStorageTransaction::InMemory { db, .. } => {
                let mut store = db.borrow_mut();
                let store = store.entry(E::COLLECTION_NAME.into()).or_default();
                let removed = store.remove(key);
                Ok(removed.is_some())
            }
        }
    }
}
