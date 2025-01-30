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
    connection::KeystoreDatabaseConnection,
    entities::{
        Entity, EntityBase, EntityFindParams, EntityTransactionExt, PersistedMlsGroup, PersistedMlsGroupExt,
        PersistedMlsPendingGroup, StringEntityId,
    },
    CryptoKeystoreResult, MissingKeyErrorKind,
};

#[async_trait::async_trait(?Send)]
impl PersistedMlsGroupExt for PersistedMlsGroup {
    fn parent_id(&self) -> Option<&[u8]> {
        self.parent_id.as_deref()
    }
}

#[async_trait::async_trait(?Send)]
impl EntityBase for PersistedMlsPendingGroup {
    type ConnectionType = KeystoreDatabaseConnection;
    type AutoGeneratedFields = ();
    const COLLECTION_NAME: &'static str = "mls_pending_groups";

    fn to_missing_key_err_kind() -> MissingKeyErrorKind {
        MissingKeyErrorKind::MlsPendingGroup
    }

    fn to_transaction_entity(self) -> crate::transaction::dynamic_dispatch::Entity {
        crate::transaction::dynamic_dispatch::Entity::PersistedMlsPendingGroup(self)
    }
}

#[async_trait::async_trait(?Send)]
impl EntityTransactionExt for PersistedMlsPendingGroup {}

#[async_trait::async_trait(?Send)]
impl Entity for PersistedMlsPendingGroup {
    fn id_raw(&self) -> &[u8] {
        self.id.as_slice()
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

    async fn find_many(
        conn: &mut Self::ConnectionType,
        _ids: &[StringEntityId],
    ) -> crate::CryptoKeystoreResult<Vec<Self>> {
        // Plot twist: we always select ALL the persisted groups. Unsure if we want to make it a real API with selection
        conn.storage().get_all(Self::COLLECTION_NAME, None).await
    }

    async fn count(conn: &mut Self::ConnectionType) -> crate::CryptoKeystoreResult<usize> {
        conn.storage().count(Self::COLLECTION_NAME).await
    }

    fn id(&self) -> CryptoKeystoreResult<wasm_bindgen::JsValue> {
        Ok(js_sys::Uint8Array::from(self.id.as_slice()).into())
    }

    fn encrypt(&mut self, cipher: &aes_gcm::Aes256Gcm) -> CryptoKeystoreResult<()> {
        self.state = self.encrypt_data(cipher, self.state.as_slice())?;

        Ok(())
    }

    fn decrypt(&mut self, cipher: &aes_gcm::Aes256Gcm) -> CryptoKeystoreResult<()> {
        self.state = self.decrypt_data(cipher, self.state.as_slice())?;

        Ok(())
    }
}
