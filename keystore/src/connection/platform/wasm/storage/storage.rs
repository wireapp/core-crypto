use aes_gcm::KeyInit as _;
use idb::TransactionMode;
use js_sys::Uint8Array;
use serde::de::DeserializeOwned;
use sha2::Digest as _;
use wasm_bindgen::JsValue;

use super::{super::WasmConnection, WasmStorageWrapper};
use crate::{
    CryptoKeystoreResult,
    connection::DatabaseKey,
    traits::{Decryptable, Decrypting, Entity as NewEntity},
};

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

impl Drop for WasmEncryptedStorage {
    fn drop(&mut self) {
        match &self.storage {
            WasmStorageWrapper::Persistent(idb) => {
                idb.close();
            }
            WasmStorageWrapper::InMemory(map) => {
                map.borrow_mut().clear();
            }
        }
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
        match &self.storage {
            WasmStorageWrapper::Persistent(idb) => {
                idb.close();
            }
            WasmStorageWrapper::InMemory(map) => {
                map.borrow_mut().clear();
            }
        }
        Ok(())
    }

    /// Count the number of entities in this storage.
    pub async fn new_count<E>(&self) -> CryptoKeystoreResult<u32>
    where
        E: NewEntity<ConnectionType = WasmConnection>,
    {
        match &self.storage {
            WasmStorageWrapper::Persistent(idb) => {
                let transaction = idb.transaction(&[E::COLLECTION_NAME], TransactionMode::ReadOnly)?;
                let store = transaction.object_store(E::COLLECTION_NAME)?;
                let request = store.count(None)?;
                let data = request.await?;

                Ok(data)
            }
            WasmStorageWrapper::InMemory(map) => Ok(map
                .borrow()
                .get(E::COLLECTION_NAME)
                .map(|v| v.values().len() as _)
                .unwrap_or_default()),
        }
    }

    /// Get the instance of `E` whose primary key serializes to `key`.
    ///
    /// Note that `key`'s type is not directly tied to `E`. We don't know if `E` implements
    /// `BorrowPrimaryKey` or not, and without specialization, we can't just do the right thing
    /// and accept the more general form. But we do know the primary key and its borrowed form
    /// both implement `KeyType`, so it's always safe to accept a byte reference.
    ///
    /// We're forced to require that `E`'s decryptable form is `DeserializeOwned`, not just `Deserialize`.
    /// This is an annoying limitation, because it obviates the work done to ensure that a decrypting instance
    /// could borrow from serialized data without necessarily copying everything.
    /// We can't really get around it, though: it stems from the `T: DeserializeOwned` bound in
    /// [`serde_wasm_bindgen::from_value`].
    //
    // After putting some thought into it, I'd prefer not to redesign the `Decrypting` trait, though.
    // There's always the chance that `serde_wasm_bindgen` will relax that restriction, at which point
    // we can just relax this bound and all will be good.
    pub async fn new_get<'a, E>(&self, key: impl AsRef<[u8]>) -> CryptoKeystoreResult<Option<E>>
    where
        E: NewEntity<ConnectionType = WasmConnection> + Decryptable<'a>,
        <E as Decryptable<'a>>::DecryptableFrom: DeserializeOwned,
    {
        let key = key.as_ref();
        let js_value = match &self.storage {
            WasmStorageWrapper::Persistent(idb) => {
                let transaction = idb.transaction(&[E::COLLECTION_NAME], TransactionMode::ReadOnly)?;
                let store = transaction.object_store(E::COLLECTION_NAME)?;
                let id = Uint8Array::from(key);
                let Some(js_value) = store.get(JsValue::from(id))?.await? else {
                    return Ok(None);
                };
                js_value
            }
            WasmStorageWrapper::InMemory(map) => {
                let map = map.borrow();
                let Some(store) = map.get(E::COLLECTION_NAME) else {
                    return Ok(None);
                };
                let Some(js_value) = store.get(key).cloned() else {
                    return Ok(None);
                };
                js_value
            }
        };

        let decryptable_entity = serde_wasm_bindgen::from_value::<E::DecryptableFrom>(js_value)?;
        let entity = decryptable_entity.decrypt(&self.cipher)?;

        Ok(Some(entity))
    }

    /// Get all instances of `E` from the database.
    pub async fn new_get_all<'a, E>(&self) -> CryptoKeystoreResult<Vec<E>>
    where
        E: NewEntity<ConnectionType = WasmConnection> + Decryptable<'a>,
        <E as Decryptable<'a>>::DecryptableFrom: DeserializeOwned,
    {
        self.new_get_all_with_query(None).await
    }

    /// Get all instance of `E` from the database, limiting to the key or key range specified in `query`.
    ///
    /// This has the same `DeserializeOwned` limitation that [`Self::new_get`] does; see documentation
    /// there for details.
    pub async fn new_get_all_with_query<'a, E>(&self, query: Option<idb::Query>) -> CryptoKeystoreResult<Vec<E>>
    where
        E: NewEntity<ConnectionType = WasmConnection> + Decryptable<'a>,
        <E as Decryptable<'a>>::DecryptableFrom: DeserializeOwned,
    {
        let js_values = match &self.storage {
            WasmStorageWrapper::Persistent(idb) => {
                let transaction = idb.transaction(&[E::COLLECTION_NAME], TransactionMode::ReadOnly)?;
                let store = transaction.object_store(E::COLLECTION_NAME)?;
                store.get_all(query, None)?.await?
            }
            WasmStorageWrapper::InMemory(map) => {
                let map = map.borrow();
                map.get(E::COLLECTION_NAME)
                    .map(|v| {
                        v.values().cloned()
                        // Annoying that we have to allocate a vector of the collected values instead of just
                        // iterating over borrowed values, but that's the simplest way to keep compat with
                        // the idb version
                        .collect()
                    })
                    .unwrap_or_default()
            }
        };

        js_values
            .into_iter()
            .map(|js_value| {
                serde_wasm_bindgen::from_value::<E::DecryptableFrom>(js_value)
                    .map_err(Into::into)
                    .and_then(|decryptable| decryptable.decrypt(&self.cipher))
            })
            .collect()
    }
}
