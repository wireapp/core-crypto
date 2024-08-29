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

use crate::{
    connection::{storage::WasmStorageWrapper, DatabaseConnection, KeystoreDatabaseConnection},
    entities::{Entity, EntityBase, EntityFindParams, MlsCredential, MlsCredentialExt, StringEntityId},
    CryptoKeystoreError, CryptoKeystoreResult, MissingKeyErrorKind,
};
use rexie::TransactionMode;

#[cfg_attr(target_family = "wasm", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_family = "wasm"), async_trait::async_trait)]
impl EntityBase for MlsCredential {
    type ConnectionType = KeystoreDatabaseConnection;
    type AutoGeneratedFields = u64;
    const COLLECTION_NAME: &'static str = "mls_credentials";

    fn to_missing_key_err_kind() -> MissingKeyErrorKind {
        MissingKeyErrorKind::MlsCredential
    }

    async fn find_all(conn: &mut Self::ConnectionType, params: EntityFindParams) -> CryptoKeystoreResult<Vec<Self>> {
        let storage = conn.storage();
        storage.get_all(Self::COLLECTION_NAME, Some(params)).await
    }

    async fn save(&self, conn: &mut Self::ConnectionType) -> crate::CryptoKeystoreResult<()> {
        let _ = self.insert(conn).await?;
        Ok(())
    }

    async fn insert(&self, conn: &mut Self::ConnectionType) -> CryptoKeystoreResult<Self::AutoGeneratedFields> {
        let storage = conn.storage_mut();

        let now = fluvio_wasm_timer::SystemTime::now();
        let created_at = now
            .duration_since(fluvio_wasm_timer::UNIX_EPOCH)
            .map_err(|_| CryptoKeystoreError::TimestampError)?
            .as_secs();

        let mut to_insert = self.clone();
        to_insert.created_at = created_at;

        storage.save(Self::COLLECTION_NAME, &mut [to_insert]).await?;

        Ok(created_at)
    }

    async fn find_one(
        conn: &mut Self::ConnectionType,
        id: &StringEntityId,
    ) -> crate::CryptoKeystoreResult<Option<Self>> {
        conn.storage().get(Self::COLLECTION_NAME, id.as_slice()).await
    }

    async fn count(conn: &mut Self::ConnectionType) -> crate::CryptoKeystoreResult<usize> {
        conn.storage().count(Self::COLLECTION_NAME).await
    }

    async fn delete(conn: &mut Self::ConnectionType, ids: &[StringEntityId]) -> crate::CryptoKeystoreResult<()> {
        let storage = conn.storage_mut();
        let ids: Vec<Vec<u8>> = ids.iter().map(StringEntityId::to_bytes).collect();
        storage.delete(Self::COLLECTION_NAME, &ids).await
    }
}

impl Entity for MlsCredential {
    fn id_raw(&self) -> &[u8] {
        self.id.as_slice()
    }

    fn encrypt(&mut self, cipher: &aes_gcm::Aes256Gcm) -> CryptoKeystoreResult<()> {
        self.credential = Self::encrypt_data(cipher, self.credential.as_slice(), self.aad())?;
        Self::ConnectionType::check_buffer_size(self.credential.len())?;

        Ok(())
    }

    fn decrypt(&mut self, cipher: &aes_gcm::Aes256Gcm) -> CryptoKeystoreResult<()> {
        self.credential = Self::decrypt_data(cipher, self.credential.as_slice(), self.aad())?;

        Ok(())
    }
}

#[async_trait::async_trait(?Send)]
impl MlsCredentialExt for MlsCredential {
    async fn delete_by_credential(conn: &mut Self::ConnectionType, credential: Vec<u8>) -> CryptoKeystoreResult<()> {
        let storage = conn.storage_mut();
        let (collection, index) = (Self::COLLECTION_NAME, "credential");
        match &mut storage.storage {
            WasmStorageWrapper::Persistent(rexie) => {
                let transaction = rexie.transaction(&[collection], TransactionMode::ReadWrite)?;
                let store = transaction.store(collection)?;
                let store_index = store.index(index)?;
                let credential_js: wasm_bindgen::JsValue = js_sys::Uint8Array::from(&credential[..]).into();
                let Some(entity_raw) = store_index.get(credential_js).await? else {
                    let reason = "'credential' in 'mls_credentials' collection";
                    let value = hex::encode(&credential);
                    return Err(CryptoKeystoreError::NotFound(reason, value));
                };

                let mut credential = serde_wasm_bindgen::from_value::<MlsCredential>(entity_raw)?;
                credential.decrypt(&storage.cipher)?;

                let id = js_sys::Uint8Array::from(credential.id.as_slice());
                store.delete(id.into()).await?;
            }
            WasmStorageWrapper::InMemory(_) => {
                // current table model does not fit in a hashmap (no more primary key)
                // memory keystore is never used in prod
            }
        }

        Ok(())
    }
}
