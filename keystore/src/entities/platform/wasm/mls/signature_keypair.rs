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
    entities::{Entity, EntityBase, EntityFindParams, EntityTransactionExt, MlsSignatureKeyPair, StringEntityId},
    CryptoKeystoreResult, MissingKeyErrorKind,
};

#[async_trait::async_trait(?Send)]
impl EntityBase for MlsSignatureKeyPair {
    type ConnectionType = KeystoreDatabaseConnection;
    type AutoGeneratedFields = ();
    const COLLECTION_NAME: &'static str = "mls_signature_keypairs";

    fn to_missing_key_err_kind() -> MissingKeyErrorKind {
        MissingKeyErrorKind::MlsSignatureKeyPair
    }

    fn to_transaction_entity(self) -> crate::transaction::dynamic_dispatch::Entity {
        crate::transaction::dynamic_dispatch::Entity::SignatureKeyPair(self)
    }
}

#[async_trait::async_trait(?Send)]
impl EntityTransactionExt for MlsSignatureKeyPair {}

#[async_trait::async_trait(?Send)]
impl Entity for MlsSignatureKeyPair {
    fn id_raw(&self) -> &[u8] {
        self.pk.as_slice()
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

    fn encrypt(&mut self, cipher: &aes_gcm::Aes256Gcm) -> CryptoKeystoreResult<()> {
        self.keypair = self.encrypt_data(cipher, self.keypair.as_slice())?;
        Self::ConnectionType::check_buffer_size(self.keypair.len())?;

        Ok(())
    }

    fn decrypt(&mut self, cipher: &aes_gcm::Aes256Gcm) -> CryptoKeystoreResult<()> {
        self.keypair = self.decrypt_data(cipher, self.keypair.as_slice())?;

        Ok(())
    }
}
