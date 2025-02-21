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

use js_sys::Uint8Array;
use rexie::TransactionMode;
use std::collections::HashMap;
use wasm_bindgen::JsValue;

use crate::keystore_v_1_0_0::{
    CryptoKeystoreResult,
    entities::{Entity, EntityFindParams},
};

use super::WasmConnection;

pub enum WasmStorageWrapper {
    Persistent(rexie::Rexie),
    InMemory(HashMap<String, HashMap<Vec<u8>, JsValue>>),
}

impl std::fmt::Debug for WasmStorageWrapper {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self {
            Self::Persistent(rexie) => f
                .debug_tuple("WasmStorageWrapper::Persistent")
                .field(&rexie.name())
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
            WasmStorageWrapper::Persistent(rexie) => {
                rexie.close();
            }
            WasmStorageWrapper::InMemory(mut map) => {
                map.clear();
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
            WasmStorageWrapper::Persistent(rexie) => {
                let transaction = rexie.transaction(&[collection], TransactionMode::ReadOnly)?;
                let store = transaction.store(collection)?;
                let id = id.as_ref().to_vec();
                let js_key = js_sys::Uint8Array::from(id.as_slice());

                if let Some(entity_raw) = store.get(js_key.into()).await? {
                    let mut entity: R = serde_wasm_bindgen::from_value(entity_raw)?;
                    entity.decrypt(&self.cipher)?;

                    Ok(Some(entity))
                } else {
                    Ok(None)
                }
            }
            WasmStorageWrapper::InMemory(map) => {
                if let Some(store) = map.get(collection) {
                    if let Some(js_value) = store.get(id.as_ref()).cloned() {
                        if let Some(mut entity) = serde_wasm_bindgen::from_value::<Option<R>>(js_value)? {
                            entity.decrypt(&self.cipher)?;
                            return Ok(Some(entity));
                        }
                    }
                }

                Ok(None)
            }
        }
    }

    pub async fn get_all<R: Entity<ConnectionType = WasmConnection> + 'static>(
        &self,
        collection: &str,
        params: Option<EntityFindParams>,
    ) -> CryptoKeystoreResult<Vec<R>> {
        match &self.storage {
            WasmStorageWrapper::Persistent(rexie) => {
                let transaction = rexie.transaction(&[collection], TransactionMode::ReadOnly)?;
                let store = transaction.store(collection)?;

                let params = params.unwrap_or_default();
                let raw_data = store
                    .scan(
                        None,
                        params.limit,
                        params.offset,
                        if params.reverse {
                            Some(rexie::Direction::Prev)
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
            WasmStorageWrapper::Persistent(rexie) => {
                let transaction = rexie.transaction(&[collection], TransactionMode::ReadOnly)?;
                let store = transaction.store(collection)?;
                let data = store.count(None).await?;

                Ok(data as usize)
            }
            WasmStorageWrapper::InMemory(map) => Ok(map.get(collection).map(|v| v.values().len()).unwrap_or_default()),
        }
    }

    pub async fn save<R: Entity<ConnectionType = WasmConnection> + 'static>(
        &mut self,
        collection: &str,
        values: &mut [R],
    ) -> CryptoKeystoreResult<()> {
        let serializer = serde_wasm_bindgen::Serializer::json_compatible();
        match &mut self.storage {
            WasmStorageWrapper::Persistent(rexie) => {
                let transaction = rexie.transaction(&[collection], TransactionMode::ReadWrite)?;
                let store = transaction.store(collection)?;

                for value in values {
                    let key = value.id()?;
                    value.encrypt(&self.cipher)?;
                    let js_value = value.serialize(&serializer)?;
                    store.put(&js_value, Some(&key)).await?;
                }
            }
            WasmStorageWrapper::InMemory(map) => {
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
            WasmStorageWrapper::Persistent(rexie) => {
                let transaction = rexie.transaction(&[collection], TransactionMode::ReadWrite)?;
                let store = transaction.store(collection)?;
                for k in ids {
                    let k = Uint8Array::from(k.as_ref());
                    store.delete(k.into()).await?;
                }
            }
            WasmStorageWrapper::InMemory(map) => {
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
