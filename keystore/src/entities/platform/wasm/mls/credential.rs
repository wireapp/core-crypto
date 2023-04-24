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
    entities::{Entity, EntityBase, EntityFindParams, MlsCredential, StringEntityId},
    CryptoKeystoreResult, MissingKeyErrorKind,
};

#[async_trait::async_trait(?Send)]
impl EntityBase for MlsCredential {
    type ConnectionType = KeystoreDatabaseConnection;

    fn to_missing_key_err_kind() -> MissingKeyErrorKind {
        MissingKeyErrorKind::MlsCredential
    }

    async fn find_all(conn: &mut Self::ConnectionType, params: EntityFindParams) -> CryptoKeystoreResult<Vec<Self>> {
        let storage = conn.storage();
        storage.get_all("mls_credentials", Some(params)).await
    }

    async fn save(&self, conn: &mut Self::ConnectionType) -> crate::CryptoKeystoreResult<()> {
        let storage = conn.storage_mut();
        storage.save("mls_credentials", &mut [self.clone()]).await?;

        Ok(())
    }

    async fn find_one(
        conn: &mut Self::ConnectionType,
        id: &StringEntityId,
    ) -> crate::CryptoKeystoreResult<Option<Self>> {
        conn.storage().get("mls_credentials", id.as_slice()).await
    }

    async fn count(conn: &mut Self::ConnectionType) -> crate::CryptoKeystoreResult<usize> {
        conn.storage().count("mls_credentials").await
    }

    async fn delete(conn: &mut Self::ConnectionType, ids: &[StringEntityId]) -> crate::CryptoKeystoreResult<()> {
        let storage = conn.storage_mut();
        let ids: Vec<Vec<u8>> = ids.iter().map(StringEntityId::to_bytes).collect();
        storage.delete("mls_credentials", &ids).await
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
