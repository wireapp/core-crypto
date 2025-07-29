use aes_gcm::KeyInit as _;
use idb::TransactionMode;
use js_sys::Uint8Array;
use sha2::Digest as _;
use std::{cell::RefCell, collections::HashMap, rc::Rc};
use wasm_bindgen::JsValue;

use crate::{
    CryptoKeystoreError, CryptoKeystoreResult,
    connection::DatabaseKey,
    entities::{Entity, EntityFindParams},
};

use super::WasmConnection;

type InMemoryDB = HashMap<String, HashMap<Vec<u8>, JsValue>>;

pub enum WasmStorageWrapper {
    Persistent(idb::Database),
    InMemory(Rc<RefCell<InMemoryDB>>),
}

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
        match self {
            WasmStorageTransaction::Persistent { tx, cipher } => {
                entity.encrypt(cipher)?;
                let js_value = entity.serialize(&serializer)?;
                let store = tx.object_store(collection_name)?;
                store.put(&js_value, None)?.await?;
            }
            WasmStorageTransaction::InMemory { db, cipher } => {
                entity.encrypt(cipher)?;
                let js_value = entity.serialize(&serializer)?;
                let mut map = db.borrow_mut();
                let entry = map.entry(collection_name.into()).or_default();
                let id = entity.id_raw().to_vec();
                entry.insert(id, js_value);
            }
        }
        Ok(())
    }
}

impl std::fmt::Debug for WasmStorageWrapper {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self {
            Self::Persistent(idb) => f
                .debug_tuple("WasmStorageWrapper::Persistent")
                .field(&idb.name())
                .finish(),
            Self::InMemory(map) => f.debug_tuple("WasmStorageWrapper::InMemory").field(map).finish(),
        }
    }
}

pub struct WasmEncryptedStorage {
    pub(crate) storage: WasmStorageWrapper,
    pub(crate) cipher: aes_gcm::Aes256Gcm,
}

impl std::fmt::Debug for WasmEncryptedStorage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WasmEncryptedStorage")
            .field("storage", &self.storage)
            .field("cipher", &"[REDACTED]")
            .finish()
    }
}

impl WasmEncryptedStorage {
    pub fn new(key: &DatabaseKey, storage: WasmStorageWrapper) -> Self {
        let cipher = aes_gcm::Aes256Gcm::new(key.as_ref().into());
        Self { cipher, storage }
    }

    pub fn new_with_pre_v4_key(key: &str, storage: WasmStorageWrapper) -> Self {
        let cipher = aes_gcm::Aes256Gcm::new(&sha2::Sha256::digest(key));
        Self { cipher, storage }
    }

    pub fn is_persistent(&self) -> bool {
        match self.storage {
            WasmStorageWrapper::Persistent(_) => true,
            WasmStorageWrapper::InMemory(_) => false,
        }
    }

    pub fn wrapper(&self) -> &WasmStorageWrapper {
        &self.storage
    }

    pub fn close(self) -> CryptoKeystoreResult<()> {
        match self.storage {
            WasmStorageWrapper::Persistent(idb) => {
                idb.close();
            }
            WasmStorageWrapper::InMemory(map) => {
                map.borrow_mut().clear();
            }
        }
        Ok(())
    }

    pub async fn get<R: Entity<ConnectionType = WasmConnection> + 'static>(
        &self,
        collection: &str,
        id: impl AsRef<[u8]>,
    ) -> CryptoKeystoreResult<Option<R>> {
        match &self.storage {
            WasmStorageWrapper::Persistent(idb) => {
                let transaction = idb.transaction(&[collection], TransactionMode::ReadOnly)?;
                let store = transaction.object_store(collection)?;
                let id = Uint8Array::from(id.as_ref());
                let get_store_request = store.get(JsValue::from(id))?;
                if let Some(entity_raw) = get_store_request.await? {
                    let mut entity: R = serde_wasm_bindgen::from_value(entity_raw)?;
                    entity.decrypt(&self.cipher)?;

                    Ok(Some(entity))
                } else {
                    Ok(None)
                }
            }
            WasmStorageWrapper::InMemory(map) => {
                let map = map.borrow();
                let Some(store) = map.get(collection) else {
                    return Ok(None);
                };
                let Some(js_value) = store.get(id.as_ref()).cloned() else {
                    return Ok(None);
                };
                let Some(mut entity) = serde_wasm_bindgen::from_value::<Option<R>>(js_value)? else {
                    return Ok(None);
                };
                entity.decrypt(&self.cipher)?;
                Ok(Some(entity))
            }
        }
    }

    pub async fn get_all<R: Entity<ConnectionType = WasmConnection> + 'static>(
        &self,
        collection: &str,
        params: Option<EntityFindParams>,
    ) -> CryptoKeystoreResult<Vec<R>> {
        self.get_all_with_query(collection, None::<JsValue>, params).await
    }

    pub(crate) async fn get_all_with_query<R: Entity<ConnectionType = WasmConnection> + 'static>(
        &self,
        collection: &str,
        query: Option<impl Into<idb::Query>>,
        params: Option<EntityFindParams>,
    ) -> CryptoKeystoreResult<Vec<R>> {
        match &self.storage {
            WasmStorageWrapper::Persistent(idb) => {
                let transaction = idb.transaction(&[collection], TransactionMode::ReadOnly)?;
                let store = transaction.object_store(collection)?;
                let params = params.unwrap_or_default();
                let mut data = store
                    .get_all(query.map(Into::into), params.limit)?
                    .await?
                    .into_iter()
                    .filter_map(|v| serde_wasm_bindgen::from_value::<R>(v).ok())
                    .filter_map(|mut entity| entity.decrypt(&self.cipher).ok().map(|_| entity));

                let data: &mut dyn Iterator<Item = R> = if params.reverse { &mut data.rev() } else { &mut data };

                Ok(data.collect())
            }
            WasmStorageWrapper::InMemory(map) => Ok(map
                .borrow()
                .get(collection)
                .map(|v| {
                    v.values()
                        .cloned()
                        .filter_map(|v| {
                            if let Some(mut entity) = serde_wasm_bindgen::from_value::<Option<R>>(v).ok().flatten() {
                                entity.decrypt(&self.cipher).ok()?;
                                Some(entity)
                            } else {
                                None
                            }
                        })
                        .collect::<Vec<R>>()
                })
                .unwrap_or_default()),
        }
    }

    pub async fn count(&self, collection: &str) -> CryptoKeystoreResult<usize> {
        match &self.storage {
            WasmStorageWrapper::Persistent(idb) => {
                let transaction = idb.transaction(&[collection], TransactionMode::ReadOnly)?;
                let store = transaction.object_store(collection)?;
                let request = store.count(None)?;
                let data = request.await?;

                Ok(data as usize)
            }
            WasmStorageWrapper::InMemory(map) => Ok(map
                .borrow()
                .get(collection)
                .map(|v| v.values().len())
                .unwrap_or_default()),
        }
    }
}
