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

use openmls_traits::key_store::{FromKeyStoreValue, ToKeyStoreValue};

use crate::{
    connection::Connection,
    entities::{
        EntityFindParams, MlsIdentity, MlsIdentityExt, MlsKeypackage, PersistedMlsGroup, PersistedMlsPendingGroup,
        StringEntityId,
    },
    CryptoKeystoreError, CryptoKeystoreResult, MissingKeyErrorKind,
};

/// An interface for the specialized queries in the KeyStore
#[async_trait::async_trait(?Send)]
pub trait CryptoKeystoreMls: Sized {
    /// Retrieves an identity signature from a client id
    ///
    /// # Arguments
    /// * `id` - client id
    ///
    /// # Errors
    /// Any common error that can happen during a database connection. IoError being a common error
    /// for example.
    async fn mls_load_identity_signature(&self, id: &str) -> CryptoKeystoreResult<Option<Vec<u8>>>;
    /// Saves the signature and credentials for a client id
    ///
    /// # Arguments
    /// * `id` - client id
    /// * `signature` - the signature to be stored
    /// * `credential` - the credential to be stored
    ///
    /// # Errors
    /// Any common error that can happen during a database connection. IoError being a common error
    /// for example.
    async fn mls_save_identity_signature(
        &self,
        id: &str,
        signature: &[u8],
        credential: &[u8],
    ) -> CryptoKeystoreResult<()>;
    /// Counts how many KeyPackages are stored
    ///
    /// # Errors
    /// Any common error that can happen during a database connection. IoError being a common error
    /// for example.
    async fn mls_keypackagebundle_count(&self) -> CryptoKeystoreResult<usize>;
    /// Fetches Keypackages
    ///
    /// # Arguments
    /// * `count` - amount of entries to be returned
    ///
    /// # Errors
    /// Any common error that can happen during a database connection. IoError being a common error
    /// for example.
    async fn mls_fetch_keypackage_bundles<V: FromKeyStoreValue>(&self, count: u32) -> CryptoKeystoreResult<Vec<V>>;
    /// Fetches a singles keypackage
    ///
    /// # Errors
    /// Any common error that can happen during a database connection. IoError being a common error
    /// for example.
    async fn mls_get_keypackage<V: FromKeyStoreValue>(&self) -> CryptoKeystoreResult<V>;
    /// Persists a `MlsGroup`
    ///
    /// # Arguments
    /// * `group_id` - group/conversation id
    /// * `state` - the group state
    ///
    /// # Errors
    /// Any common error that can happen during a database connection. IoError being a common error
    /// for example.
    async fn mls_group_persist(&self, group_id: &[u8], state: &[u8]) -> CryptoKeystoreResult<()>;
    /// Loads `MlsGroups` from the database. It will be returned as a `HashMap` where the key is
    /// the group/conversation id and the value the group state
    ///
    /// # Errors
    /// Any common error that can happen during a database connection. IoError being a common error
    /// for example.
    async fn mls_groups_restore(&self) -> CryptoKeystoreResult<std::collections::HashMap<Vec<u8>, Vec<u8>>>;
    /// Deletes `MlsGroups` from the database.
    /// # Errors
    /// Any common error that can happen during a database connection. IoError being a common error
    /// for example.
    async fn mls_group_delete(&self, group_id: &[u8]) -> CryptoKeystoreResult<()>;
    /// Saves a `MlsGroup` in a temporary table (typically used in scenarios where the group cannot
    /// be commited until the backend acknowledges it, like external commits)
    ///
    /// # Arguments
    /// * `group_id` - group/conversation id
    /// * `mls_group` - the group/conversation state
    ///
    /// # Errors
    /// Any common error that can happen during a database connection. IoError being a common error
    /// for example.
    async fn mls_pending_groups_save(&self, group_id: &[u8], mls_group: &[u8]) -> CryptoKeystoreResult<()>;
    /// Loads a temporary `MlsGroup` from the database
    ///
    /// # Arguments
    /// * `id` - group/conversation id
    ///
    /// # Errors
    /// Any common error that can happen during a database connection. IoError being a common error
    /// for example.
    async fn mls_pending_groups_load(&self, group_id: &[u8]) -> CryptoKeystoreResult<Vec<u8>>;
    /// Deletes a temporary `MlsGroup` from the database
    ///
    /// # Arguments
    /// * `id` - group/conversation id
    ///
    /// # Errors
    /// Any common error that can happen during a database connection. IoError being a common error
    /// for example.
    async fn mls_pending_groups_delete(&self, group_id: &[u8]) -> CryptoKeystoreResult<()>;
}

#[inline(always)]
fn bytes_to_string_id(raw: &[u8]) -> String {
    StringEntityId::new(raw).as_hex_string()
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
    pub async fn mls_store_keypackage_bundle(
        &self,
        key: openmls::prelude::KeyPackageBundle,
    ) -> CryptoKeystoreResult<()> {
        let id = key.key_package().external_key_id()?;
        use openmls_traits::key_store::OpenMlsKeyStore as _;
        self.store(id, &key).await?;

        Ok(())
    }
}

#[async_trait::async_trait(?Send)]
impl CryptoKeystoreMls for crate::connection::Connection {
    // TODO: Review zero on drop behavior here
    async fn mls_load_identity_signature(&self, id: &str) -> CryptoKeystoreResult<Option<Vec<u8>>> {
        Ok(self
            .find(id.as_bytes())
            .await?
            .map(|id: MlsIdentity| id.signature.clone()))
    }

    async fn mls_save_identity_signature(
        &self,
        id: &str,
        signature: &[u8],
        credential: &[u8],
    ) -> CryptoKeystoreResult<()> {
        let identity = MlsIdentity {
            id: id.into(),
            signature: signature.into(),
            credential: credential.into(),
        };

        self.save(identity).await?;
        Ok(())
    }

    async fn mls_keypackagebundle_count(&self) -> CryptoKeystoreResult<usize> {
        self.count::<MlsKeypackage>().await
    }

    #[cfg(target_family = "wasm")]
    async fn mls_fetch_keypackage_bundles<V: FromKeyStoreValue>(&self, count: u32) -> CryptoKeystoreResult<Vec<V>> {
        use crate::{connection::storage::WasmStorageWrapper, entities::Entity};
        let conn = self.conn.lock_arc().await;
        let cipher = &conn.storage().cipher;
        let storage = &conn.storage().storage;

        let raw_kps: Vec<MlsKeypackage> = match storage {
            WasmStorageWrapper::Persistent(rexie) => {
                let transaction = rexie.transaction(&["mls_keys"], rexie::TransactionMode::ReadOnly)?;
                let store = transaction.store("mls_keys")?;
                let items_fut = store.get_all(None, Some(count), None, Some(rexie::Direction::Next));

                let items = items_fut.await?;

                if items.is_empty() {
                    return Ok(vec![]);
                }

                let kps = items
                    .into_iter()
                    .map(|(_k, v)| {
                        let mut kp: MlsKeypackage = serde_wasm_bindgen::from_value(v)?;
                        kp.decrypt(cipher)?;
                        Ok(kp)
                    })
                    .collect::<CryptoKeystoreResult<Vec<MlsKeypackage>>>()?;

                CryptoKeystoreResult::Ok(kps)
            }
            WasmStorageWrapper::InMemory(map) => {
                if let Some(collection) = map.get("mls_keys") {
                    let kps = collection
                        .iter()
                        .take(count as usize)
                        .map(|(_k, v)| {
                            let mut entity: MlsKeypackage = serde_wasm_bindgen::from_value(v.clone())?;
                            entity.decrypt(cipher)?;
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
    async fn mls_get_keypackage<V: FromKeyStoreValue>(&self) -> CryptoKeystoreResult<V> {
        use crate::{connection::storage::WasmStorageWrapper, entities::Entity};
        let conn = self.conn.lock_arc().await;
        let cipher = conn.storage().cipher.clone();
        let storage = &conn.storage().storage;

        let raw_kp: MlsKeypackage = match storage {
            WasmStorageWrapper::Persistent(rexie) => {
                let transaction = rexie.transaction(&["mls_keys"], rexie::TransactionMode::ReadOnly)?;
                let store = transaction.store("mls_keys")?;

                let items_fut = store.get_all(None, Some(1), None, Some(rexie::Direction::Next));

                let items = items_fut.await?;

                if items.is_empty() {
                    return Err(CryptoKeystoreError::OutOfKeyPackageBundles);
                }

                let (_, js_kp) = items[0].clone();
                let mut kp: MlsKeypackage = serde_wasm_bindgen::from_value(js_kp)?;
                kp.decrypt(&cipher)?;

                drop(items);

                transaction.commit().await?;

                Ok(kp)
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
            .map_err(|e| CryptoKeystoreError::KeyStoreValueTransformError(Box::new(e)))?)
    }

    #[cfg(not(target_family = "wasm"))]
    async fn mls_fetch_keypackage_bundles<V: FromKeyStoreValue>(&self, count: u32) -> CryptoKeystoreResult<Vec<V>> {
        let db = self.conn.lock().await;

        let mut stmt = db.prepare_cached("SELECT id FROM mls_keys ORDER BY rowid DESC LIMIT ?")?;

        let kpb_ids: Vec<String> = stmt
            .query_map([count], |r| r.get(0))?
            .map(|r| r.map_err(CryptoKeystoreError::from))
            .collect::<CryptoKeystoreResult<Vec<String>>>()?;

        drop(stmt);
        drop(db);

        let keypackages: Vec<MlsKeypackage> = self.find_many(&kpb_ids).await?;

        Ok(keypackages
            .into_iter()
            .filter_map(|kpb| V::from_key_store_value(&kpb.key).ok())
            .collect())
    }

    #[cfg(not(target_family = "wasm"))]
    async fn mls_get_keypackage<V: FromKeyStoreValue>(&self) -> CryptoKeystoreResult<V> {
        if self.mls_keypackagebundle_count().await? == 0 {
            return Err(CryptoKeystoreError::OutOfKeyPackageBundles);
        }

        let db = self.conn.lock().await;
        let rowid: i64 = db.query_row("SELECT rowid FROM mls_keys ORDER BY rowid ASC LIMIT 1", [], |r| {
            r.get(0)
        })?;

        let mut blob = db.blob_open(rusqlite::DatabaseName::Main, "mls_keys", "key", rowid, true)?;
        use std::io::Read as _;
        let mut buf = Vec::with_capacity(blob.len());
        blob.read_to_end(&mut buf)?;
        blob.close()?;

        V::from_key_store_value(&buf).map_err(|e| CryptoKeystoreError::KeyStoreValueTransformError(Box::new(e)))
    }

    async fn mls_group_persist(&self, group_id: &[u8], state: &[u8]) -> CryptoKeystoreResult<()> {
        self.save(PersistedMlsGroup {
            id: group_id.into(),
            state: state.into(),
        })
        .await?;

        Ok(())
    }

    async fn mls_group_delete(&self, group_id: &[u8]) -> CryptoKeystoreResult<()> {
        self.remove::<PersistedMlsGroup, _>(group_id).await?;

        Ok(())
    }

    // TODO: Review zero on drop behavior
    async fn mls_groups_restore(&self) -> CryptoKeystoreResult<std::collections::HashMap<Vec<u8>, Vec<u8>>> {
        let groups = self.find_all::<PersistedMlsGroup>(EntityFindParams::default()).await?;
        Ok(groups
            .into_iter()
            .map(|group: PersistedMlsGroup| (group.id.clone(), group.state.clone()))
            .collect())
    }

    async fn mls_pending_groups_save(&self, group_id: &[u8], mls_group: &[u8]) -> CryptoKeystoreResult<()> {
        self.save(PersistedMlsPendingGroup {
            id: group_id.into(),
            state: mls_group.into(),
        })
        .await?;
        Ok(())
    }

    async fn mls_pending_groups_load(&self, group_id: &[u8]) -> CryptoKeystoreResult<Vec<u8>> {
        let group = self
            .find(group_id)
            .await?
            .map(|r: PersistedMlsPendingGroup| r.state.clone())
            .ok_or(CryptoKeystoreError::MissingKeyInStore(
                MissingKeyErrorKind::MlsPendingGroup,
            ))?;
        Ok(group)
    }

    async fn mls_pending_groups_delete(&self, group_id: &[u8]) -> CryptoKeystoreResult<()> {
        self.remove::<PersistedMlsPendingGroup, _>(group_id).await
    }
}

#[async_trait::async_trait(?Send)]
impl openmls_traits::key_store::OpenMlsKeyStore for crate::connection::Connection {
    type Error = CryptoKeystoreError;

    async fn store<V: openmls_traits::key_store::ToKeyStoreValue>(&self, k: &[u8], v: &V) -> Result<(), Self::Error>
    where
        Self: Sized,
    {
        if k.is_empty() {
            return Err(CryptoKeystoreError::MlsKeyStoreError(
                "The provided key is empty".into(),
            ));
        }

        let data = v
            .to_key_store_value()
            .map_err(|e| CryptoKeystoreError::KeyStoreValueTransformError(Box::new(e)))?;
        let type_name = std::any::type_name::<V>();

        let id = bytes_to_string_id(k);

        match type_name {
            "openmls::key_packages::KeyPackageBundle" => {
                let kp = MlsKeypackage { id, key: data };
                self.save(kp).await?;
            }
            _ => unreachable!("OpenMlsKeyStore::store: Unsupported ToKeyStoreValue type"),
        }

        Ok(())
    }

    async fn read<V: FromKeyStoreValue>(&self, k: &[u8]) -> Option<V>
    where
        Self: Sized,
    {
        if k.is_empty() {
            return None;
        }

        let type_name = std::any::type_name::<V>();

        let hydrated_ksv = match type_name {
            "openmls::key_packages::KeyPackageBundle" => {
                let keypackage_id = bytes_to_string_id(k);

                #[cfg(feature = "memory-cache")]
                if self.is_cache_enabled() {
                    if let Some(mut cache) = self.memory_cache.try_lock() {
                        if let Some(value) = cache
                            .get(&Self::mls_cache_key(k))
                            .and_then(|buf| V::from_key_store_value(buf).ok())
                        {
                            return Some(value);
                        }
                    }
                }

                let kp: MlsKeypackage = self.find(keypackage_id).await.ok().flatten()?;

                #[cfg(feature = "memory-cache")]
                if self.is_cache_enabled() {
                    let mut cache = self.memory_cache.lock().await;
                    cache.put(Self::mls_cache_key(k), kp.key.clone());
                }

                V::from_key_store_value(&kp.key).ok()?
            }
            "openmls::credentials::CredentialBundle" => {
                use crate::entities::MlsIdentityExt as _;
                let mut conn = self.borrow_conn().await.ok()?;

                let identity = MlsIdentity::find_by_signature(&mut conn, k).await.ok().flatten()?;

                V::from_key_store_value(&identity.credential).ok()?
            }
            _ => unreachable!("OpenMlsKeyStore::read: Unsupported FromKeyStoreValue type"),
        };

        Some(hydrated_ksv)
    }

    async fn delete<V: ToKeyStoreValue>(&self, k: &[u8]) -> Result<(), Self::Error> {
        if k.is_empty() {
            return Ok(());
        }
        let id = bytes_to_string_id(k);

        #[cfg(feature = "memory-cache")]
        if self.is_cache_enabled() {
            let _ = self.memory_cache.lock().await.pop(&Self::mls_cache_key(&k));
        }

        let type_name = std::any::type_name::<V>();

        match type_name {
            "openmls::key_packages::KeyPackageBundle" => {
                self.remove::<MlsKeypackage, _>(id.clone()).await?;
            }
            "openmls::credentials::CredentialBundle" => {
                let mut conn = self.borrow_conn().await?;
                MlsIdentity::delete_by_signature(&mut conn, k).await?;
            }
            _ => unreachable!("OpenMlsKeyStore::delete: Unsupported FromKeyStoreValue type"),
        }

        Ok(())
    }
}
