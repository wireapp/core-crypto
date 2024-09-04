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
    entities::{E2eiRefreshToken, Entity, EntityBase, EntityFindParams, StringEntityId, UniqueEntity},
    CryptoKeystoreError, CryptoKeystoreResult, MissingKeyErrorKind,
};

#[cfg_attr(target_family = "wasm", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_family = "wasm"), async_trait::async_trait)]
impl EntityBase for E2eiRefreshToken {
    type ConnectionType = KeystoreDatabaseConnection;
    type AutoGeneratedFields = ();
    const COLLECTION_NAME: &'static str = "e2ei_refresh_token";

    fn to_missing_key_err_kind() -> MissingKeyErrorKind {
        MissingKeyErrorKind::E2eiRefreshToken
    }

    async fn find_all(_conn: &mut Self::ConnectionType, _params: EntityFindParams) -> CryptoKeystoreResult<Vec<Self>> {
        return Err(CryptoKeystoreError::NotImplemented);
    }

    async fn save(&self, _conn: &mut Self::ConnectionType) -> crate::CryptoKeystoreResult<()> {
        return Err(CryptoKeystoreError::NotImplemented);
    }

    async fn find_one(
        _conn: &mut Self::ConnectionType,
        _id: &StringEntityId,
    ) -> crate::CryptoKeystoreResult<Option<Self>> {
        return Err(CryptoKeystoreError::NotImplemented);
    }

    async fn count(_conn: &mut Self::ConnectionType) -> crate::CryptoKeystoreResult<usize> {
        return Err(CryptoKeystoreError::NotImplemented);
    }

    async fn delete(_conn: &mut Self::ConnectionType, _ids: &[StringEntityId]) -> crate::CryptoKeystoreResult<()> {
        return Err(CryptoKeystoreError::NotImplemented);
    }
}

impl Entity for E2eiRefreshToken {
    fn id_raw(&self) -> &[u8] {
        &Self::ID
    }

    fn encrypt(&mut self, cipher: &aes_gcm::Aes256Gcm) -> CryptoKeystoreResult<()> {
        self.content = self.encrypt_data(cipher, self.content.as_slice())?;
        Self::ConnectionType::check_buffer_size(self.content.len())?;
        Ok(())
    }

    fn decrypt(&mut self, cipher: &aes_gcm::Aes256Gcm) -> CryptoKeystoreResult<()> {
        self.content = self.decrypt_data(cipher, self.content.as_slice())?;
        Ok(())
    }
}

#[cfg_attr(target_family = "wasm", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_family = "wasm"), async_trait::async_trait)]
impl UniqueEntity for E2eiRefreshToken {
    async fn find_unique(conn: &mut Self::ConnectionType) -> CryptoKeystoreResult<Self> {
        Ok(conn
            .storage()
            .get(Self::COLLECTION_NAME, &Self::ID)
            .await?
            .ok_or(CryptoKeystoreError::NotFound("refresh token", "".to_string()))?)
    }

    async fn replace(&self, conn: &mut Self::ConnectionType) -> CryptoKeystoreResult<()> {
        let storage = conn.storage_mut();
        storage.save(Self::COLLECTION_NAME, &mut [self.clone()]).await?;
        Ok(())
    }
}
