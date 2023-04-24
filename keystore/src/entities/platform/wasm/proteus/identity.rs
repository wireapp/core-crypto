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
    entities::{Entity, EntityBase, EntityFindParams, ProteusIdentity, StringEntityId},
    CryptoKeystoreResult, MissingKeyErrorKind,
};

#[async_trait::async_trait(?Send)]
impl EntityBase for ProteusIdentity {
    type ConnectionType = KeystoreDatabaseConnection;

    fn to_missing_key_err_kind() -> MissingKeyErrorKind {
        MissingKeyErrorKind::ProteusIdentity
    }

    async fn find_all(conn: &mut Self::ConnectionType, _params: EntityFindParams) -> CryptoKeystoreResult<Vec<Self>> {
        let storage = conn.storage();
        storage.get_all("proteus_identities", None).await
    }

    async fn save(&self, conn: &mut Self::ConnectionType) -> crate::CryptoKeystoreResult<()> {
        let storage = conn.storage_mut();
        storage.save("proteus_identities", &mut [self.clone()]).await
    }

    async fn find_one(
        conn: &mut Self::ConnectionType,
        _id: &StringEntityId,
    ) -> crate::CryptoKeystoreResult<Option<Self>> {
        let mut identities = Self::find_all(conn, EntityFindParams::default()).await?;
        if identities.is_empty() {
            Ok(None)
        } else {
            Ok(identities.pop())
        }
    }

    async fn count(conn: &mut Self::ConnectionType) -> crate::CryptoKeystoreResult<usize> {
        let storage = conn.storage();
        storage.count("proteus_identities").await
    }

    async fn delete(conn: &mut Self::ConnectionType, ids: &[StringEntityId]) -> crate::CryptoKeystoreResult<()> {
        let storage = conn.storage_mut();
        let ids: Vec<Vec<u8>> = ids.iter().map(StringEntityId::to_bytes).collect();
        storage.delete("proteus_identities", &ids).await
    }
}

impl Entity for ProteusIdentity {
    fn id_raw(&self) -> &[u8] {
        &[1u8]
    }

    fn encrypt(&mut self, cipher: &aes_gcm::Aes256Gcm) -> CryptoKeystoreResult<()> {
        self.pk = Self::encrypt_data(cipher, self.pk.as_slice(), self.aad())?;
        Self::ConnectionType::check_buffer_size(self.pk.len())?;

        self.sk = Self::encrypt_data(cipher, self.sk.as_slice(), self.aad())?;
        Self::ConnectionType::check_buffer_size(self.sk.len())?;

        Ok(())
    }

    fn decrypt(&mut self, cipher: &aes_gcm::Aes256Gcm) -> CryptoKeystoreResult<()> {
        self.pk = Self::decrypt_data(cipher, self.pk.as_slice(), self.aad())?;
        self.sk = Self::decrypt_data(cipher, self.sk.as_slice(), self.aad())?;

        Ok(())
    }
}
