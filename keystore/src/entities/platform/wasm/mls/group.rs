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
    connection::{DatabaseConnection, KeystoreDatabaseConnection},
    entities::{
        Entity, EntityBase, EntityFindParams, PersistedMlsGroup, PersistedMlsGroupExt, PersistedMlsPendingGroup,
        StringEntityId,
    },
    CryptoKeystoreResult, MissingKeyErrorKind,
};

#[async_trait::async_trait(?Send)]
impl EntityBase for PersistedMlsGroup {
    type ConnectionType = KeystoreDatabaseConnection;

    fn to_missing_key_err_kind() -> MissingKeyErrorKind {
        MissingKeyErrorKind::MlsGroup
    }

    async fn find_all(conn: &mut Self::ConnectionType, params: EntityFindParams) -> CryptoKeystoreResult<Vec<Self>> {
        let storage = conn.storage();
        storage.get_all("mls_groups", Some(params)).await
    }

    async fn save(&self, conn: &mut Self::ConnectionType) -> crate::CryptoKeystoreResult<()> {
        let storage = conn.storage_mut();
        storage.save("mls_groups", &mut [self.clone()]).await
    }

    async fn find_one(
        conn: &mut Self::ConnectionType,
        id: &StringEntityId,
    ) -> crate::CryptoKeystoreResult<Option<Self>> {
        let storage = conn.storage();
        storage.get("mls_groups", id.as_bytes()).await
    }

    async fn find_many(
        conn: &mut Self::ConnectionType,
        _ids: &[StringEntityId],
    ) -> crate::CryptoKeystoreResult<Vec<Self>> {
        let storage = conn.storage();
        // Plot twist: we always select ALL the persisted groups. Unsure if we want to make it a real API with selection
        storage.get_all("mls_groups", None).await
    }

    async fn count(conn: &mut Self::ConnectionType) -> crate::CryptoKeystoreResult<usize> {
        let storage = conn.storage();
        storage.count("mls_groups").await
    }

    async fn delete(conn: &mut Self::ConnectionType, ids: &[StringEntityId]) -> crate::CryptoKeystoreResult<()> {
        let storage = conn.storage_mut();
        let ids: Vec<Vec<u8>> = ids.iter().map(StringEntityId::as_bytes).collect();
        let _ = storage.delete("mls_groups", &ids).await?;
        Ok(())
    }
}

impl Entity for PersistedMlsGroup {
    fn id_raw(&self) -> &[u8] {
        self.id.as_slice()
    }

    fn encrypt(&mut self, cipher: &aes_gcm::Aes256Gcm) -> CryptoKeystoreResult<()> {
        self.state = Self::encrypt_data(cipher, self.state.as_slice(), self.aad())?;
        Self::ConnectionType::check_buffer_size(self.state.len())?;

        Ok(())
    }

    fn decrypt(&mut self, cipher: &aes_gcm::Aes256Gcm) -> CryptoKeystoreResult<()> {
        self.state = Self::decrypt_data(cipher, self.state.as_slice(), self.aad())?;

        Ok(())
    }
}

#[async_trait::async_trait(?Send)]
impl PersistedMlsGroupExt for PersistedMlsGroup {
    fn parent_id(&self) -> Option<&[u8]> {
        self.parent_id.as_ref().map(Vec::as_slice)
    }

    // async fn child_groups(&self, conn: &mut <Self as EntityBase>::ConnectionType) -> CryptoKeystoreResult<Vec<Self>> {
    //     let id = self.id_raw();
    //     let storage = conn.storage();
    //     let entities = storage.get_indexed("mls_groups", "parent_id", id).await?;
    //     Ok(entities)
    // }
}

#[async_trait::async_trait(?Send)]
impl EntityBase for PersistedMlsPendingGroup {
    type ConnectionType = KeystoreDatabaseConnection;

    fn to_missing_key_err_kind() -> MissingKeyErrorKind {
        MissingKeyErrorKind::MlsGroup
    }

    async fn find_all(conn: &mut Self::ConnectionType, params: EntityFindParams) -> CryptoKeystoreResult<Vec<Self>> {
        let storage = conn.storage();
        storage.get_all("mls_pending_groups", Some(params)).await
    }

    async fn save(&self, conn: &mut Self::ConnectionType) -> crate::CryptoKeystoreResult<()> {
        let storage = conn.storage_mut();

        storage.save("mls_pending_groups", &mut [self.clone()]).await?;

        Ok(())
    }

    async fn find_one(
        conn: &mut Self::ConnectionType,
        id: &StringEntityId,
    ) -> crate::CryptoKeystoreResult<Option<Self>> {
        conn.storage().get("mls_pending_groups", id.as_bytes()).await
    }

    async fn find_many(
        conn: &mut Self::ConnectionType,
        _ids: &[StringEntityId],
    ) -> crate::CryptoKeystoreResult<Vec<Self>> {
        // Plot twist: we always select ALL the persisted groups. Unsure if we want to make it a real API with selection
        conn.storage().get_all("mls_pending_groups", None).await
    }

    async fn count(conn: &mut Self::ConnectionType) -> crate::CryptoKeystoreResult<usize> {
        conn.storage().count("mls_pending_groups").await
    }

    async fn delete(conn: &mut Self::ConnectionType, ids: &[StringEntityId]) -> crate::CryptoKeystoreResult<()> {
        let ids: Vec<Vec<u8>> = ids.iter().map(StringEntityId::as_bytes).collect();
        let _ = conn.storage_mut().delete("mls_pending_groups", &ids).await?;
        Ok(())
    }
}

impl Entity for PersistedMlsPendingGroup {
    fn id_raw(&self) -> &[u8] {
        self.id.as_slice()
    }

    fn id(&self) -> CryptoKeystoreResult<wasm_bindgen::JsValue> {
        Ok(js_sys::Uint8Array::from(self.id.as_slice()).into())
    }

    fn aad(&self) -> &[u8] {
        self.id.as_slice()
    }

    fn encrypt(&mut self, cipher: &aes_gcm::Aes256Gcm) -> CryptoKeystoreResult<()> {
        self.state = Self::encrypt_data(cipher, self.state.as_slice(), self.aad())?;

        Ok(())
    }

    fn decrypt(&mut self, cipher: &aes_gcm::Aes256Gcm) -> CryptoKeystoreResult<()> {
        self.state = Self::decrypt_data(cipher, self.state.as_slice(), self.aad())?;

        Ok(())
    }
}
