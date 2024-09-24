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
    entities::{E2eiEnrollment, Entity, EntityBase, EntityFindParams, EntityMlsExt, StringEntityId},
    CryptoKeystoreError, CryptoKeystoreResult, MissingKeyErrorKind,
};

#[cfg_attr(target_family = "wasm", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_family = "wasm"), async_trait::async_trait)]
impl EntityBase for E2eiEnrollment {
    type ConnectionType = KeystoreDatabaseConnection;
    type AutoGeneratedFields = ();
    const COLLECTION_NAME: &'static str = "e2ei_enrollment";

    fn to_missing_key_err_kind() -> MissingKeyErrorKind {
        MissingKeyErrorKind::E2eiEnrollment
    }

    fn to_transaction_entity(self) -> crate::transaction::Entity {
        crate::transaction::Entity::E2eiEnrollment(self)
    }

    async fn find_all(_conn: &mut Self::ConnectionType, _params: EntityFindParams) -> CryptoKeystoreResult<Vec<Self>> {
        Err(CryptoKeystoreError::ImplementationError)
    }

    async fn find_one(conn: &mut Self::ConnectionType, id: &StringEntityId) -> CryptoKeystoreResult<Option<Self>> {
        conn.storage().get(Self::COLLECTION_NAME, id.as_slice()).await
    }

    async fn count(_conn: &mut Self::ConnectionType) -> CryptoKeystoreResult<usize> {
        Err(CryptoKeystoreError::ImplementationError)
    }
}

#[cfg_attr(target_family = "wasm", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_family = "wasm"), async_trait::async_trait)]
impl EntityMlsExt for E2eiEnrollment {}

impl Entity for E2eiEnrollment {
    fn id_raw(&self) -> &[u8] {
        &self.id[..]
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
