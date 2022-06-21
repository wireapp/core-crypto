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

use openmls_traits::key_store::FromKeyStoreValue;

use crate::{
    connection::Connection,
    entities::{MlsIdentity, MlsKeypackage, PersistedMlsGroup, StringEntityId},
    CryptoKeystoreError, CryptoKeystoreResult,
};

pub trait CryptoKeystoreMls {
    fn mls_load_identity_signature(&self, id: &str) -> CryptoKeystoreResult<Option<Vec<u8>>>;
    fn mls_save_identity_signature(&self, id: &str, signature: &[u8], credential: &[u8]) -> CryptoKeystoreResult<()>;
    fn mls_keypackagebundle_count(&self) -> CryptoKeystoreResult<usize>;
    fn mls_fetch_keypackage_bundles<V: FromKeyStoreValue>(&self, count: u32) -> CryptoKeystoreResult<Vec<V>>;
    fn mls_get_keypackage<V: FromKeyStoreValue>(&self) -> CryptoKeystoreResult<V>;
    fn mls_group_persist(&self, group_id: &[u8], state: &[u8]) -> CryptoKeystoreResult<()>;
    fn mls_groups_restore(&self) -> CryptoKeystoreResult<std::collections::HashMap<Vec<u8>, Vec<u8>>>;
    fn mls_fetch_keypackage_bundle_by_ref<V: FromKeyStoreValue, K: AsRef<[u8]>>(
        &self,
        href: K,
    ) -> CryptoKeystoreResult<Option<V>>;
}

impl Connection {
    #[cfg(feature = "memory-cache")]
    #[inline(always)]
    fn mls_cache_key(k: &[u8]) -> Vec<u8> {
        let mut ret = vec![0; 4 + k.len()];
        ret[..4].copy_from_slice(b"mls:");
        ret[4..].copy_from_slice(k);
        ret
    }

    #[cfg(test)]
    pub fn mls_store_keypackage_bundle(&self, key: openmls::prelude::KeyPackageBundle) -> CryptoKeystoreResult<()> {
        let id = key.key_package().external_key_id()?;
        use openmls_traits::key_store::OpenMlsKeyStore as _;
        self.store(id, &key).map_err(CryptoKeystoreError::MlsKeyStoreError)?;

        Ok(())
    }
}

impl CryptoKeystoreMls for crate::connection::Connection {
    fn mls_load_identity_signature(&self, id: &str) -> CryptoKeystoreResult<Option<Vec<u8>>> {
        Ok(self.find(id.as_bytes())?.map(|id: MlsIdentity| id.signature))
    }

    fn mls_save_identity_signature(&self, id: &str, signature: &[u8], credential: &[u8]) -> CryptoKeystoreResult<()> {
        let identity = MlsIdentity {
            id: id.into(),
            signature: signature.into(),
            credential: credential.into(),
        };

        self.insert(identity)?;
        Ok(())
    }

    fn mls_keypackagebundle_count(&self) -> CryptoKeystoreResult<usize> {
        self.count::<MlsKeypackage>()
    }

    #[cfg(target_family = "wasm")]
    fn mls_fetch_keypackage_bundles<V: FromKeyStoreValue>(&self, count: u32) -> CryptoKeystoreResult<Vec<V>> {
        use crate::{connection::storage::WasmStorageWrapper, entities::Entity};
        let cipher = self
            .conn
            .lock()
            .map_err(|_| CryptoKeystoreError::LockPoisonError)?
            .storage()
            .cipher
            .clone();
        let raw_kps: Vec<MlsKeypackage> = match &self
            .conn
            .lock()
            .map_err(|_| CryptoKeystoreError::LockPoisonError)?
            .storage()
            .storage
        {
            WasmStorageWrapper::Persistent(rexie) => {
                let transaction = rexie.transaction(&["mls_keys"], rexie::TransactionMode::ReadOnly)?;
                let store = transaction.store("mls_keys")?;

                let kps: Vec<MlsKeypackage> = crate::syncify!(async move {
                    let items = store
                        .get_all(None, Some(count), Some(1), Some(rexie::Direction::Next))
                        .await?;

                    if items.is_empty() {
                        return Ok(vec![]);
                    }

                    let kps = items
                        .into_iter()
                        .map(|(_k, v)| {
                            let mut kp: MlsKeypackage = serde_wasm_bindgen::from_value(v)?;
                            kp.decrypt(&cipher)?;
                            Ok(kp)
                        })
                        .collect::<CryptoKeystoreResult<Vec<MlsKeypackage>>>()?;

                    CryptoKeystoreResult::Ok(kps)
                })?;

                CryptoKeystoreResult::Ok(kps)
            }
            WasmStorageWrapper::InMemory(map) => {
                if let Some(collection) = map.get("mls_keys") {
                    let kps = collection
                        .iter()
                        .take(count as usize)
                        .map(|(_k, v)| {
                            let mut entity: MlsKeypackage = serde_wasm_bindgen::from_value(v.clone())?;
                            entity.decrypt(&cipher)?;
                            Ok(entity)
                        })
                        .collect::<CryptoKeystoreResult<Vec<MlsKeypackage>>>()?;

                    Ok(kps)
                } else {
                    Ok(vec![])
                }
            }
        }?;

        Ok(raw_kps
            .into_iter()
            .filter_map(|kpb| V::from_key_store_value(&kpb.key).ok())
            .collect())
    }

    #[cfg(target_family = "wasm")]
    fn mls_get_keypackage<V: FromKeyStoreValue>(&self) -> CryptoKeystoreResult<V> {
        use crate::{connection::storage::WasmStorageWrapper, entities::Entity};
        let cipher = self
            .conn
            .lock()
            .map_err(|_| CryptoKeystoreError::LockPoisonError)?
            .storage()
            .cipher
            .clone();
        let raw_kp: MlsKeypackage = match &self
            .conn
            .lock()
            .map_err(|_| CryptoKeystoreError::LockPoisonError)?
            .storage()
            .storage
        {
            WasmStorageWrapper::Persistent(rexie) => {
                let transaction = rexie.transaction(&["mls_keys"], rexie::TransactionMode::ReadOnly)?;
                let store = transaction.store("mls_keys")?;
                let res = crate::syncify!(async move {
                    let items = store
                        .get_all(None, Some(1), Some(1), Some(rexie::Direction::Next))
                        .await?;

                    if items.is_empty() {
                        return Err(CryptoKeystoreError::OutOfKeyPackageBundles);
                    }

                    let (_, js_kp) = items[0].clone();
                    let mut kp: MlsKeypackage = serde_wasm_bindgen::from_value(js_kp)?;
                    kp.decrypt(&cipher)?;
                    Ok(kp)
                })?;

                Ok(res)
            }
            WasmStorageWrapper::InMemory(map) => {
                if let Some(collection) = map.get("mls_keys") {
                    if let Some((_, js_kp)) = collection.iter().next() {
                        let mut entity: MlsKeypackage = serde_wasm_bindgen::from_value(js_kp.clone())?;
                        entity.decrypt(&cipher)?;
                        Ok(entity)
                    } else {
                        Err(CryptoKeystoreError::OutOfKeyPackageBundles)
                    }
                } else {
                    Err(CryptoKeystoreError::OutOfKeyPackageBundles)
                }
            }
        }?;

        Ok(V::from_key_store_value(&raw_kp.key)
            .map_err(|e| CryptoKeystoreError::KeyStoreValueTransformError(e.into()))?)
    }

    #[cfg(not(target_family = "wasm"))]
    fn mls_fetch_keypackage_bundles<V: FromKeyStoreValue>(&self, count: u32) -> CryptoKeystoreResult<Vec<V>> {
        let db = self.conn.lock().map_err(|_| CryptoKeystoreError::LockPoisonError)?;

        let mut stmt = db.prepare_cached("SELECT id FROM mls_keys ORDER BY rowid DESC LIMIT ?")?;

        let kpb_ids: Vec<String> = stmt
            .query_map([count], |r| r.get(0))?
            .map(|r| r.map_err(CryptoKeystoreError::from))
            .collect::<CryptoKeystoreResult<Vec<String>>>()?;

        drop(stmt);
        drop(db);

        Ok(self
            .find_many::<MlsKeypackage, _>(&kpb_ids)?
            .into_iter()
            .filter_map(|kpb| V::from_key_store_value(&kpb.key).ok())
            .collect())
    }

    #[cfg(not(target_family = "wasm"))]
    fn mls_get_keypackage<V: FromKeyStoreValue>(&self) -> CryptoKeystoreResult<V> {
        if self.mls_keypackagebundle_count()? == 0 {
            return Err(CryptoKeystoreError::OutOfKeyPackageBundles);
        }

        let db = self.conn.lock().map_err(|_| CryptoKeystoreError::LockPoisonError)?;
        let rowid: i64 = db.query_row("SELECT rowid FROM mls_keys ORDER BY rowid ASC LIMIT 1", [], |r| {
            r.get(0)
        })?;

        let mut blob = db.blob_open(rusqlite::DatabaseName::Main, "mls_keys", "key", rowid, true)?;
        use std::io::Read as _;
        let mut buf = vec![];
        blob.read_to_end(&mut buf)?;
        blob.close()?;

        V::from_key_store_value(&buf).map_err(|e| CryptoKeystoreError::KeyStoreValueTransformError(e.into()))
    }

    fn mls_group_persist(&self, group_id: &[u8], state: &[u8]) -> CryptoKeystoreResult<()> {
        self.insert(PersistedMlsGroup {
            id: group_id.into(),
            state: state.into(),
        })?;

        Ok(())
    }

    fn mls_groups_restore(&self) -> CryptoKeystoreResult<std::collections::HashMap<Vec<u8>, Vec<u8>>> {
        let groups = self.find_many::<PersistedMlsGroup, &[u8]>(&[])?;
        Ok(groups
            .into_iter()
            .map(|group: PersistedMlsGroup| (group.id, group.state))
            .collect())
    }

    fn mls_fetch_keypackage_bundle_by_ref<V: FromKeyStoreValue, K: AsRef<[u8]>>(
        &self,
        href: K,
    ) -> CryptoKeystoreResult<Option<V>> {
        Ok(self
            .find(href.as_ref())?
            .and_then(|v: MlsKeypackage| V::from_key_store_value(&v.key).ok()))
    }
}

impl openmls_traits::key_store::OpenMlsKeyStore for crate::connection::Connection {
    type Error = String;

    fn store<V: openmls_traits::key_store::ToKeyStoreValue>(&self, k: &[u8], v: &V) -> Result<(), Self::Error>
    where
        Self: Sized,
    {
        if k.is_empty() {
            return Err("The provided key is empty".into());
        }

        let data = v.to_key_store_value().map_err(Into::into)?;
        let type_name = std::any::type_name::<V>();

        let id =
            String::from_utf8(k.into()).map_or_else(|_| StringEntityId::new(k).as_hex_string(), std::convert::identity);

        match type_name {
            "openmls::key_packages::KeyPackageBundle" => {
                let kp = MlsKeypackage { id, key: data };
                self.insert(kp).map_err(|e| e.to_string())?;
            }
            _ => unreachable!("Unsupported ToKeyStoreValue type"),
        }

        Ok(())
    }

    fn read<V: FromKeyStoreValue>(&self, k: &[u8]) -> Option<V>
    where
        Self: Sized,
    {
        if k.is_empty() {
            return None;
        }

        let type_name = std::any::type_name::<V>();

        let hydrated_ksv = match type_name {
            "openmls::key_packages::KeyPackageBundle" => {
                let keypackage_id = String::from_utf8(k.into())
                    .map_or_else(|_| StringEntityId::new(k).as_hex_string(), std::convert::identity);

                #[cfg(feature = "memory-cache")]
                if self.is_cache_enabled() {
                    if let Ok(mut cache) = self.memory_cache.lock() {
                        if let Some(value) = cache
                            .get(&Self::mls_cache_key(k))
                            .and_then(|buf| V::from_key_store_value(buf).ok())
                        {
                            return Some(value);
                        }
                    }
                }

                let kp: MlsKeypackage = self.find(keypackage_id).ok().flatten()?;

                #[cfg(feature = "memory-cache")]
                if self.is_cache_enabled() {
                    if let Ok(mut cache) = self.memory_cache.lock() {
                        cache.put(Self::mls_cache_key(k), kp.key.clone());
                    }
                }

                V::from_key_store_value(&kp.key).ok()?
            }
            "openmls::credentials::CredentialBundle" => {
                use crate::entities::MlsIdentityExt as _;
                let mut conn = self.borrow_conn().ok()?;
                let identity = MlsIdentity::find_by_signature(&mut conn, k).ok().flatten()?;

                V::from_key_store_value(&identity.credential).ok()?
            }
            _ => unreachable!("Unsupported FromKeyStoreValue type"),
        };

        Some(hydrated_ksv)
    }

    fn delete(&self, k: &[u8]) -> Result<(), Self::Error> {
        if k.is_empty() {
            return Ok(());
        }
        let id =
            String::from_utf8(k.into()).map_or_else(|_| StringEntityId::new(k).as_hex_string(), std::convert::identity);

        #[cfg(feature = "memory-cache")]
        if self.is_cache_enabled() {
            let _ = self
                .memory_cache
                .lock()
                .map_err(|_| CryptoKeystoreError::LockPoisonError.to_string())?
                .pop(&Self::mls_cache_key(&k));
        }

        match self.remove::<MlsKeypackage, _>(id.clone()) {
            Ok(_) => {
                return Ok(());
            }
            Err(CryptoKeystoreError::MissingKeyInStore(crate::MissingKeyErrorKind::MlsKeyBundle)) => {
                self.remove::<MlsIdentity, _>(id).map_err(|e| e.to_string())?;
                Ok(())
            }
            Err(e) => {
                return Err(e.to_string());
            }
        }
    }
}
