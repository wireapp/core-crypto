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

use crate::entities::{PersistedMlsGroup, StringEntityId};
use crate::{
    connection::KeystoreDatabaseConnection,
    entities::{Entity, EntityBase},
};
use crate::{CryptoKeystoreResult, MissingKeyErrorKind};

#[async_trait::async_trait(?Send)]
impl EntityBase for PersistedMlsGroup {
    type ConnectionType = KeystoreDatabaseConnection;

    fn to_missing_key_err_kind() -> MissingKeyErrorKind {
        MissingKeyErrorKind::MlsGroup
    }

    async fn save(&self, conn: &mut Self::ConnectionType) -> crate::CryptoKeystoreResult<()> {
        let storage = conn.storage_mut();

        storage.save("mls_groups", &mut [self.clone()]).await?;

        Ok(())
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
        storage.get_all("mls_groups").await
    }

    async fn count(conn: &mut Self::ConnectionType) -> crate::CryptoKeystoreResult<usize> {
        let storage = conn.storage();
        storage.count("mls_groups").await
    }

    async fn delete(conn: &mut Self::ConnectionType, id: &StringEntityId) -> crate::CryptoKeystoreResult<()> {
        let storage = conn.storage_mut();
        let _ = storage.delete("mls_groups", &[id.as_bytes()]).await?;
        Ok(())
    }
}

impl Entity for PersistedMlsGroup {
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
