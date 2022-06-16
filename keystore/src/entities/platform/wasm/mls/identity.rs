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

use crate::entities::{MlsIdentity, MlsIdentityExt, StringEntityId};
use crate::{
    connection::KeystoreDatabaseConnection,
    entities::{Entity, EntityBase},
};
use crate::{CryptoKeystoreResult, MissingKeyErrorKind};

#[async_trait::async_trait(?Send)]
impl EntityBase for MlsIdentity {
    type ConnectionType = KeystoreDatabaseConnection;

    fn to_missing_key_err_kind() -> MissingKeyErrorKind {
        MissingKeyErrorKind::MlsIdentityBundle
    }

    async fn save(&self, conn: &mut Self::ConnectionType) -> crate::CryptoKeystoreResult<()> {
        let storage = conn.storage_mut();
        storage.save("mls_identities", &mut [self.clone()]).await?;

        Ok(())
    }

    async fn find_one(
        conn: &mut Self::ConnectionType,
        id: &StringEntityId,
    ) -> crate::CryptoKeystoreResult<Option<Self>> {
        conn.storage().get("mls_identities", id.as_bytes()).await
    }

    async fn find_many(
        _conn: &mut Self::ConnectionType,
        _ids: &[StringEntityId],
    ) -> crate::CryptoKeystoreResult<Vec<Self>> {
        unimplemented!("There is only one identity within a keystore, so this won't be implemented")
    }

    async fn count(conn: &mut Self::ConnectionType) -> crate::CryptoKeystoreResult<usize> {
        conn.storage().count("mls_identities").await
    }

    async fn delete(conn: &mut Self::ConnectionType, id: &StringEntityId) -> crate::CryptoKeystoreResult<()> {
        if let Some(entity) = Self::find_one(conn, id).await? {
            let _ = conn
                .storage_mut()
                .delete("mls_identities", &[entity.id.as_bytes()])
                .await?;
        }
        Ok(())
    }
}

impl Entity for MlsIdentity {
    fn aad(&self) -> &[u8] {
        self.id.as_bytes()
    }

    fn encrypt(&mut self, cipher: &aes_gcm::Aes256Gcm) -> CryptoKeystoreResult<()> {
        self.signature = Self::encrypt_data(cipher, self.signature.as_slice(), self.aad())?;
        self.credential = Self::encrypt_data(cipher, self.credential.as_slice(), self.aad())?;

        Ok(())
    }

    fn decrypt(&mut self, cipher: &aes_gcm::Aes256Gcm) -> CryptoKeystoreResult<()> {
        self.signature = Self::decrypt_data(cipher, self.signature.as_slice(), self.aad())?;
        self.credential = Self::decrypt_data(cipher, self.credential.as_slice(), self.aad())?;

        Ok(())
    }
}

#[async_trait::async_trait(?Send)]
impl MlsIdentityExt for MlsIdentity {
    async fn find_by_signature(
        conn: &mut Self::ConnectionType,
        signature: &[u8],
    ) -> CryptoKeystoreResult<Option<Self>> {
        conn.storage()
            .get_indexed("mls_identities", "signature", signature)
            .await
    }

    async fn delete_by_signature(conn: &mut Self::ConnectionType, signature: &[u8]) -> CryptoKeystoreResult<()> {
        if let Some(identity) = Self::find_by_signature(conn, signature).await? {
            let _ = conn
                .storage_mut()
                .delete("mls_identities", &[identity.id.as_bytes()])
                .await?;
        }

        Ok(())
    }
}
