// Wire
// Copyright (C) 2022 Wire Swiss GmbH

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with this program. If not, see http://www.gnu.org/licenses/.

use idb::{CursorDirection, KeyRange, ObjectStore, TransactionMode};
use js_sys::Uint8Array;
use std::{cell::RefCell, collections::HashMap, rc::Rc};
use wasm_bindgen::JsValue;

use crate::{
    CryptoKeystoreError, CryptoKeystoreResult,
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
    pub fn new(key: impl AsRef<str>, storage: WasmStorageWrapper) -> Self {
        let hashed_key: aes_gcm::Key<aes_gcm::Aes256Gcm> = {
            use sha2::Digest as _;
            let mut hasher = sha2::Sha256::new();
            hasher.update(key.as_ref().as_bytes());
            hasher.finalize()
        };

        use aes_gcm::KeyInit as _;

        let cipher = aes_gcm::Aes256Gcm::new(&hashed_key);
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

    /// Copied from Rexie.
    async fn scan(
        object_store: &ObjectStore,
        key_range: Option<KeyRange>,
        limit: Option<u32>,
        offset: Option<u32>,
        direction: Option<CursorDirection>,
    ) -> CryptoKeystoreResult<Vec<(JsValue, JsValue)>> {
        let cursor = object_store.open_cursor(key_range.map(Into::into), direction)?.await?;

        match cursor {
            None => Ok(Vec::new()),
            Some(cursor) => {
                let mut cursor = cursor.into_managed();

                let mut result = Vec::new();

                match limit {
                    Some(limit) => {
                        if let Some(offset) = offset {
                            cursor.advance(offset).await?;
                        }

                        for _ in 0..limit {
                            let key = cursor.key()?;
                            let value = cursor.value()?;

                            match (key, value) {
                                (Some(key), Some(value)) => {
                                    result.push((key, value));
                                    cursor.next(None).await?;
                                }
                                _ => break,
                            }
                        }
                    }
                    None => {
                        if let Some(offset) = offset {
                            cursor.advance(offset).await?;
                        }

                        loop {
                            let key = cursor.key()?;
                            let value = cursor.value()?;

                            match (key, value) {
                                (Some(key), Some(value)) => {
                                    result.push((key, value));
                                    cursor.next(None).await?;
                                }
                                _ => break,
                            }
                        }
                    }
                }

                Ok(result)
            }
        }
    }

    pub async fn get_all<R: Entity<ConnectionType = WasmConnection> + 'static>(
        &self,
        collection: &str,
        params: Option<EntityFindParams>,
    ) -> CryptoKeystoreResult<Vec<R>> {
        match &self.storage {
            WasmStorageWrapper::Persistent(idb) => {
                let transaction = idb.transaction(&[collection], TransactionMode::ReadOnly)?;
                let store = transaction.object_store(collection)?;

                let params = params.unwrap_or_default();
                let raw_data = Self::scan(
                    &store,
                    None,
                    params.limit,
                    params.offset,
                    if params.reverse {
                        Some(CursorDirection::Prev)
                    } else {
                        None
                    },
                )
                .await?;

                let data: Vec<R> = raw_data
                    .into_iter()
                    .filter_map(|(_, v)| {
                        if v.is_null() || v.is_undefined() {
                            None
                        } else if let Ok(mut entity) = serde_wasm_bindgen::from_value::<R>(v) {
                            entity.decrypt(&self.cipher).ok()?;
                            Some(entity)
                        } else {
                            None
                        }
                    })
                    .collect();

                Ok(data)
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

    pub async fn save<R: Entity<ConnectionType = WasmConnection> + 'static>(
        &mut self,
        collection: &str,
        values: &mut [R],
    ) -> CryptoKeystoreResult<()> {
        let serializer = serde_wasm_bindgen::Serializer::json_compatible();
        match &mut self.storage {
            WasmStorageWrapper::Persistent(idb) => {
                let transaction = idb.transaction(&[collection], TransactionMode::ReadWrite)?;
                let store = transaction.object_store(collection)?;

                for value in values {
                    let key = value.id()?;
                    value.encrypt(&self.cipher)?;
                    let js_value = value.serialize(&serializer)?;
                    let request = store.put(&js_value, Some(&key))?;
                    request.await?;
                }
            }
            WasmStorageWrapper::InMemory(map) => {
                let mut map = map.borrow_mut();
                let entry = map.entry(collection.into()).or_default();
                for v in values {
                    let js_id = v.id()?;
                    let id = js_id
                        .as_string()
                        .map(|s| CryptoKeystoreResult::Ok(s.as_bytes().into()))
                        .unwrap_or_else(|| Ok(serde_wasm_bindgen::from_value(js_id)?))?;

                    v.encrypt(&self.cipher)?;
                    let js_value = v.serialize(&serializer)?;
                    entry.insert(id, js_value);
                }
            }
        }

        Ok(())
    }

    pub async fn delete(&mut self, collection: &str, ids: &[impl AsRef<[u8]>]) -> CryptoKeystoreResult<()> {
        match &mut self.storage {
            WasmStorageWrapper::Persistent(idb) => {
                let transaction = idb.transaction(&[collection], TransactionMode::ReadWrite)?;
                let store = transaction.object_store(collection)?;
                for k in ids {
                    let k = Uint8Array::from(k.as_ref());
                    let request = store.delete(JsValue::from(k))?;
                    request.await?;
                }
            }
            WasmStorageWrapper::InMemory(map) => {
                let mut map = map.borrow_mut();
                map.entry(collection.into()).and_modify(|store| {
                    for k in ids {
                        store.remove(k.as_ref());
                    }
                });
            }
        }

        Ok(())
    }
}
