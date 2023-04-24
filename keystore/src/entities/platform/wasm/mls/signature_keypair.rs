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
    entities::{Entity, EntityBase, EntityFindParams, MlsSignatureKeyPair, MlsSignatureKeyPairExt, StringEntityId},
    CryptoKeystoreError, CryptoKeystoreResult, MissingKeyErrorKind,
};

use openmls_traits::types::SignatureScheme;

#[async_trait::async_trait(?Send)]
impl EntityBase for MlsSignatureKeyPair {
    type ConnectionType = KeystoreDatabaseConnection;

    fn to_missing_key_err_kind() -> MissingKeyErrorKind {
        MissingKeyErrorKind::MlsSignatureKeyPair
    }

    async fn find_all(conn: &mut Self::ConnectionType, params: EntityFindParams) -> CryptoKeystoreResult<Vec<Self>> {
        let storage = conn.storage();
        storage.get_all("mls_signature_keypairs", Some(params)).await
    }

    async fn save(&self, conn: &mut Self::ConnectionType) -> crate::CryptoKeystoreResult<()> {
        let storage = conn.storage_mut();
        storage.save("mls_signature_keypairs", &mut [self.clone()]).await?;

        Ok(())
    }

    async fn find_one(
        conn: &mut Self::ConnectionType,
        id: &StringEntityId,
    ) -> crate::CryptoKeystoreResult<Option<Self>> {
        conn.storage().get("mls_signature_keypairs", id.as_slice()).await
    }

    async fn count(conn: &mut Self::ConnectionType) -> crate::CryptoKeystoreResult<usize> {
        conn.storage().count("mls_signature_keypairs").await
    }

    async fn delete(conn: &mut Self::ConnectionType, ids: &[StringEntityId]) -> crate::CryptoKeystoreResult<()> {
        let storage = conn.storage_mut();
        let ids: Vec<Vec<u8>> = ids.iter().map(StringEntityId::to_bytes).collect();
        storage.delete("mls_signature_keypairs", &ids).await
    }
}

impl Entity for MlsSignatureKeyPair {
    fn id_raw(&self) -> &[u8] {
        self.pk.as_slice()
    }

    fn encrypt(&mut self, cipher: &aes_gcm::Aes256Gcm) -> CryptoKeystoreResult<()> {
        self.keypair = Self::encrypt_data(cipher, self.keypair.as_slice(), self.aad())?;
        Self::ConnectionType::check_buffer_size(self.keypair.len())?;

        Ok(())
    }

    fn decrypt(&mut self, cipher: &aes_gcm::Aes256Gcm) -> CryptoKeystoreResult<()> {
        self.keypair = Self::decrypt_data(cipher, self.keypair.as_slice(), self.aad())?;

        Ok(())
    }
}

#[async_trait::async_trait(?Send)]
impl MlsSignatureKeyPairExt for MlsSignatureKeyPair {
    async fn keypair_for_signature_scheme(
        conn: &mut Self::ConnectionType,
        credential_id: &[u8],
        signature_scheme: SignatureScheme,
    ) -> CryptoKeystoreResult<Option<Self>> {
        let storage = conn.storage();
        let Some(keypair) = storage
            .get_indexed::<Self>("mls_signature_keypairs", "signature_scheme", (signature_scheme as u16).to_be_bytes())
            .await? else {
            return Err(CryptoKeystoreError::MissingKeyInStore(MissingKeyErrorKind::MlsSignatureKeyPair));
        };

        if !keypair.credential_id.is_empty() && keypair.credential_id != credential_id {
            return Err(CryptoKeystoreError::SignatureKeyPairDoesNotBelongToCredential);
        }

        Ok(Some(keypair))
    }
}
