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
    connection::{storage::WasmStorageTransaction, DatabaseConnection, KeystoreDatabaseConnection},
    entities::{Entity, EntityBase, EntityFindParams, EntityMlsExt, MlsCredential, MlsCredentialExt, StringEntityId},
    CryptoKeystoreError, CryptoKeystoreResult, MissingKeyErrorKind,
};
use fluvio_wasm_timer::SystemTime;
use wasm_bindgen::JsValue;

#[cfg_attr(target_family = "wasm", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_family = "wasm"), async_trait::async_trait)]
impl EntityBase for MlsCredential {
    type ConnectionType = KeystoreDatabaseConnection;
    type AutoGeneratedFields = u64;
    const COLLECTION_NAME: &'static str = "mls_credentials";

    fn to_missing_key_err_kind() -> MissingKeyErrorKind {
        MissingKeyErrorKind::MlsCredential
    }

    fn to_transaction_entity(self) -> crate::transaction::Entity {
        crate::transaction::Entity::MlsCredential(self)
    }

    async fn find_all(conn: &mut Self::ConnectionType, params: EntityFindParams) -> CryptoKeystoreResult<Vec<Self>> {
        let storage = conn.storage();
        storage.get_all(Self::COLLECTION_NAME, Some(params)).await
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
}

#[cfg_attr(target_family = "wasm", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_family = "wasm"), async_trait::async_trait)]
impl EntityMlsExt for MlsCredential {
    async fn pre_save<'a>(&'a mut self) -> CryptoKeystoreResult<Self::AutoGeneratedFields> {
        let now = SystemTime::now();
        let created_at = now
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_err(|_| CryptoKeystoreError::TimestampError)?
            .as_secs();
        self.created_at = created_at;
        Ok(created_at)
    }
}

impl Entity for MlsCredential {
    fn id_raw(&self) -> &[u8] {
        self.id.as_slice()
    }

    fn encrypt(&mut self, cipher: &aes_gcm::Aes256Gcm) -> CryptoKeystoreResult<()> {
        self.credential = self.encrypt_data(cipher, self.credential.as_slice())?;
        Self::ConnectionType::check_buffer_size(self.credential.len())?;

        Ok(())
    }

    fn decrypt(&mut self, cipher: &aes_gcm::Aes256Gcm) -> CryptoKeystoreResult<()> {
        self.credential = self.decrypt_data(cipher, self.credential.as_slice())?;

        Ok(())
    }
}

#[async_trait::async_trait(?Send)]
impl MlsCredentialExt for MlsCredential {
    async fn delete_by_credential(
        transaction: &WasmStorageTransaction<'_>,
        credential: Vec<u8>,
    ) -> CryptoKeystoreResult<()> {
        match transaction {
            WasmStorageTransaction::Persistent {
                tx: transaction,
                cipher,
            } => {
                let store = transaction.object_store(Self::COLLECTION_NAME)?;
                let store_index = store.index("credential")?;
                let credential_js: wasm_bindgen::JsValue = js_sys::Uint8Array::from(&credential[..]).into();
                let request = store_index.get(credential_js)?;
                let Some(entity_raw) = request.await? else {
                    let reason = "'credential' in 'mls_credentials' collection";
                    let value = hex::encode(&credential);
                    return Err(CryptoKeystoreError::NotFound(reason, value));
                };

                let mut credential = serde_wasm_bindgen::from_value::<MlsCredential>(entity_raw)?;
                credential.decrypt(&cipher)?;

                let id = JsValue::from(credential.id.clone());
                let request = store.delete(id)?;
                request.await?;
            }
            WasmStorageTransaction::InMemory { .. } => {
                // current table model does not fit in a hashmap (no more primary key)
                // memory keystore is never used in prod
            }
        }

        Ok(())
    }
}
