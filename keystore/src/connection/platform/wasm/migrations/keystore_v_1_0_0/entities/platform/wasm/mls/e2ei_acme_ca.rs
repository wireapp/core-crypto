use crate::keystore_v_1_0_0::{
    CryptoKeystoreError, CryptoKeystoreResult, MissingKeyErrorKind,
    connection::{DatabaseConnection, KeystoreDatabaseConnection},
    entities::{E2eiAcmeCA, Entity, EntityBase, EntityFindParams, StringEntityId, UniqueEntity},
};

const ID: [u8; 1] = [0];

#[cfg_attr(target_family = "wasm", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_family = "wasm"), async_trait::async_trait)]
impl EntityBase for E2eiAcmeCA {
    type ConnectionType = KeystoreDatabaseConnection;
    type AutoGeneratedFields = ();

    fn to_missing_key_err_kind() -> MissingKeyErrorKind {
        MissingKeyErrorKind::E2eiAcmeCA
    }

    async fn find_all(_conn: &mut Self::ConnectionType, _params: EntityFindParams) -> CryptoKeystoreResult<Vec<Self>> {
        return Err(CryptoKeystoreError::NotImplemented);
    }

    async fn save(&self, _conn: &mut Self::ConnectionType) -> CryptoKeystoreResult<()> {
        return Err(CryptoKeystoreError::NotImplemented);
    }

    async fn find_one(_conn: &mut Self::ConnectionType, _id: &StringEntityId) -> CryptoKeystoreResult<Option<Self>> {
        return Err(CryptoKeystoreError::NotImplemented);
    }

    async fn count(_conn: &mut Self::ConnectionType) -> CryptoKeystoreResult<usize> {
        return Err(CryptoKeystoreError::NotImplemented);
    }

    async fn delete(_conn: &mut Self::ConnectionType, _ids: &[StringEntityId]) -> CryptoKeystoreResult<()> {
        return Err(CryptoKeystoreError::NotImplemented);
    }
}

impl Entity for E2eiAcmeCA {
    fn id_raw(&self) -> &[u8] {
        &ID
    }

    fn encrypt(&mut self, cipher: &aes_gcm::Aes256Gcm) -> CryptoKeystoreResult<()> {
        self.content = Self::encrypt_data(cipher, self.content.as_slice(), self.aad())?;
        Self::ConnectionType::check_buffer_size(self.content.len())?;
        Ok(())
    }

    fn decrypt(&mut self, cipher: &aes_gcm::Aes256Gcm) -> CryptoKeystoreResult<()> {
        self.content = Self::decrypt_data(cipher, self.content.as_slice(), self.aad())?;
        Ok(())
    }
}

#[cfg_attr(target_family = "wasm", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_family = "wasm"), async_trait::async_trait)]
impl UniqueEntity for E2eiAcmeCA {
    async fn find_unique(conn: &mut Self::ConnectionType) -> CryptoKeystoreResult<Self> {
        Ok(conn
            .storage()
            .get("e2ei_acme_ca", &ID)
            .await?
            .ok_or(CryptoKeystoreError::NotFound("E2EI ACME root CA", "".to_string()))?)
    }

    async fn replace(&self, conn: &mut Self::ConnectionType) -> CryptoKeystoreResult<()> {
        let storage = conn.storage_mut();
        storage.save("e2ei_acme_ca", &mut [self.clone()]).await?;
        Ok(())
    }
}
