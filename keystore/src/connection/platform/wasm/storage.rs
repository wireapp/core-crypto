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

use crate::{entities::Entity, CryptoKeystoreResult};

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

        use aes_gcm::NewAead as _;

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
            WasmStorageWrapper::Persistent(rexie) => Ok(rexie.close()),
            WasmStorageWrapper::InMemory(mut map) => {
                map.clear();
                Ok(())
            }
        }
    }

    pub async fn get<R: Entity<ConnectionType = WasmConnection> + 'static>(
        &self,
        collection: impl AsRef<str>,
        id: impl AsRef<[u8]>,
    ) -> CryptoKeystoreResult<Option<R>> {
        match &self.storage {
            WasmStorageWrapper::Persistent(rexie) => {
                let collection = collection.as_ref();
                let transaction = rexie.transaction(&[collection], TransactionMode::ReadOnly)?;
                let store = transaction.store(collection)?;
                let id = id.as_ref().to_vec();
                let js_key = js_sys::Uint8Array::from(id.as_slice());

                if let Some(entity_raw) = store.get(&js_key).await? {
                    let mut entity: R = serde_wasm_bindgen::from_value(entity_raw)?;
                    entity.decrypt(&self.cipher)?;

                    Ok(Some(entity))
                } else {
                    Ok(None)
                }
            }
            WasmStorageWrapper::InMemory(map) => {
                if let Some(store) = map.get(collection.as_ref()) {
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

    pub async fn get_indexed<R: Entity<ConnectionType = WasmConnection> + 'static>(
        &self,
        collection: impl AsRef<str>,
        index: impl AsRef<str>,
        id: impl AsRef<[u8]>,
    ) -> CryptoKeystoreResult<Option<R>> {
        match &self.storage {
            crate::connection::storage::WasmStorageWrapper::Persistent(rexie) => {
                let transaction = rexie.transaction(&[collection.as_ref()], rexie::TransactionMode::ReadOnly)?;
                let store = transaction.store(collection.as_ref())?;
                let store_index = store.index(index.as_ref())?;
                let id = id.as_ref();
                let js_key = js_sys::Uint8Array::from(id);

                // Optimistic case where the targeted index isn't encrypted
                if let Some(entity_raw) = store_index.get(&js_key).await? {
                    let mut entity: R = serde_wasm_bindgen::from_value(entity_raw)?;
                    entity.decrypt(&self.cipher)?;

                    Ok(Some(entity))
                } else {
                    // Extra work...
                    let records_iter = store_index
                        .get_all(None, None, None, None)
                        .await?
                        .into_iter()
                        .map(|(_, value)| value);

                    for store_value in records_iter {
                        let prop_bytes = js_sys::Reflect::get(&store_value, &index.as_ref().into())
                            .map(|prop| Uint8Array::from(prop).to_vec())?;

                        let mut entity: R = serde_wasm_bindgen::from_value(store_value)?;
                        entity.decrypt(&self.cipher)?;
                        let entity_id = entity.id_raw();

                        let decrypted_id = R::decrypt_data(&self.cipher, &prop_bytes, entity_id)?;
                        if decrypted_id == id {
                            return Ok(Some(entity));
                        }
                    }

                    Ok(None)
                }
            }
            crate::connection::storage::WasmStorageWrapper::InMemory(map) => {
                if let Some(store) = map.get(collection.as_ref()) {
                    Ok(store.iter().find_map(|(_k, v)| {
                        if !v.is_object() {
                            return None;
                        }

                        let prop_bytes = js_sys::Reflect::get(v, &index.as_ref().into())
                            .map(|prop| Uint8Array::from(prop).to_vec())
                            .ok()?;

                        let mut entity: R = serde_wasm_bindgen::from_value(v.clone()).ok()?;
                        entity.decrypt(&self.cipher).ok()?;
                        let entity_id = entity.id_raw();
                        let clear_prop_bytes = R::decrypt_data(&self.cipher, &prop_bytes, entity_id).ok()?;
                        if clear_prop_bytes == id.as_ref() {
                            if let Some(mut entity) = serde_wasm_bindgen::from_value::<Option<R>>(v.clone())
                                .ok()
                                .flatten()
                                .take()
                            {
                                entity.decrypt(&self.cipher).ok()?;
                                Some(entity)
                            } else {
                                None
                            }
                        } else {
                            None
                        }
                    }))
                } else {
                    Ok(None)
                }
            }
        }
    }

    pub async fn get_all<R: Entity<ConnectionType = WasmConnection> + 'static>(
        &self,
        collection: impl AsRef<str>,
    ) -> CryptoKeystoreResult<Vec<R>> {
        match &self.storage {
            WasmStorageWrapper::Persistent(rexie) => {
                let collection = collection.as_ref();
                let transaction = rexie.transaction(&[collection], TransactionMode::ReadOnly)?;
                let store = transaction.store(collection)?;

                let raw_data = store.get_all(None, None, None, None).await?;
                let data: Vec<R> = raw_data
                    .into_iter()
                    .filter_map(|(_, v)| {
                        if let Some(mut entity) = serde_wasm_bindgen::from_value::<Option<R>>(v).ok().flatten() {
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
                .get(collection.as_ref())
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

    pub async fn get_many<R: Entity<ConnectionType = WasmConnection> + 'static>(
        &self,
        collection: impl AsRef<str>,
        ids: &[&[u8]],
    ) -> CryptoKeystoreResult<Vec<R>> {
        match &self.storage {
            WasmStorageWrapper::Persistent(rexie) => {
                let collection = collection.as_ref();
                let transaction = rexie.transaction(&[collection], TransactionMode::ReadOnly)?;
                let store = transaction.store(collection)?;
                let ids: Vec<Vec<u8>> = ids.iter().map(|id| id.to_vec()).collect();

                let raw_data = store.get_all(None, None, None, None).await?;
                let data = raw_data
                    .into_iter()
                    .filter_map(|(k, v)| {
                        let js_key = js_sys::Uint8Array::from(k.clone());
                        let key = js_key.to_vec();
                        if !ids.contains(&key) {
                            return None;
                        }

                        if let Some(mut entity) = serde_wasm_bindgen::from_value::<Option<R>>(v).ok().flatten() {
                            entity.decrypt(&self.cipher).ok()?;
                            Some(entity)
                        } else {
                            None
                        }
                    })
                    .collect::<Vec<R>>();

                Ok(data)
            }
            WasmStorageWrapper::InMemory(map) => {
                if let Some(store) = map.get(collection.as_ref()) {
                    store
                        .iter()
                        .filter(|(k, _)| ids.contains(&k.as_slice()))
                        .map(|(_k, v)| {
                            let mut e: R = serde_wasm_bindgen::from_value(v.clone())?;
                            e.decrypt(&self.cipher)?;
                            Ok(e)
                        })
                        .collect::<CryptoKeystoreResult<Vec<R>>>()
                } else {
                    Ok(vec![])
                }
            }
        }
    }

    pub async fn count(&self, collection: impl AsRef<str>) -> CryptoKeystoreResult<usize> {
        match &self.storage {
            WasmStorageWrapper::Persistent(rexie) => {
                let collection = collection.as_ref();
                let transaction = rexie.transaction(&[collection], TransactionMode::ReadOnly)?;
                let store = transaction.store(collection)?;
                let data = store.count(None).await?;

                Ok(data as usize)
            }
            WasmStorageWrapper::InMemory(map) => Ok(map
                .get(collection.as_ref())
                .map(|v| v.values().len())
                .unwrap_or_default()),
        }
    }

    pub async fn save<R: Entity<ConnectionType = WasmConnection> + 'static>(
        &mut self,
        collection: impl AsRef<str>,
        values: &mut [R],
    ) -> CryptoKeystoreResult<()> {
        let serializer = serde_wasm_bindgen::Serializer::json_compatible();
        match &mut self.storage {
            WasmStorageWrapper::Persistent(rexie) => {
                let collection = collection.as_ref();
                let transaction = rexie.transaction(&[collection], TransactionMode::ReadWrite)?;
                let store = transaction.store(collection)?;
                let values: Vec<R> = values.iter().map(|v| v.clone()).collect();

                for mut value in values {
                    let key = value.id()?;
                    value.encrypt(&self.cipher)?;
                    let js_value = value.serialize(&serializer)?;
                    store.put(&js_value, Some(&key)).await?;
                }

                transaction.commit().await?;
            }
            WasmStorageWrapper::InMemory(map) => {
                let entry = map.entry(collection.as_ref().into()).or_default();
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

    pub async fn delete(&mut self, collection: impl AsRef<str>, ids: &[impl AsRef<[u8]>]) -> CryptoKeystoreResult<()> {
        match &mut self.storage {
            WasmStorageWrapper::Persistent(rexie) => {
                let collection = collection.as_ref();
                let transaction = rexie.transaction(&[collection], TransactionMode::ReadWrite)?;
                let store = transaction.store(collection)?;
                for k in ids {
                    let k = Uint8Array::from(k.as_ref());
                    store.delete(&k.into()).await?;
                }
                transaction.commit().await?;
            }
            WasmStorageWrapper::InMemory(map) => {
                map.entry(collection.as_ref().into()).and_modify(|store| {
                    for k in ids {
                        let result = store.remove(k.as_ref());
                        debug_assert!(result.is_some());
                    }
                });
            }
        }

        Ok(())
    }
}
