use crate::keystore_v_1_0_0::{
    CryptoKeystoreResult, MissingKeyErrorKind,
    connection::{DatabaseConnection, KeystoreDatabaseConnection},
    entities::{Entity, EntityBase, EntityFindParams, MlsPskBundle, StringEntityId},
};

#[cfg_attr(target_family = "wasm", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_family = "wasm"), async_trait::async_trait)]
impl EntityBase for MlsPskBundle {
    type ConnectionType = KeystoreDatabaseConnection;
    type AutoGeneratedFields = ();

    fn to_missing_key_err_kind() -> MissingKeyErrorKind {
        MissingKeyErrorKind::MlsPskBundle
    }

    async fn find_all(conn: &mut Self::ConnectionType, params: EntityFindParams) -> CryptoKeystoreResult<Vec<Self>> {
        let storage = conn.storage();
        storage.get_all("mls_psk_bundles", Some(params)).await
    }

    async fn save(&self, conn: &mut Self::ConnectionType) -> CryptoKeystoreResult<()> {
        let storage = conn.storage_mut();
        storage.save("mls_psk_bundles", &mut [self.clone()]).await?;

        Ok(())
    }

    async fn find_one(conn: &mut Self::ConnectionType, id: &StringEntityId) -> CryptoKeystoreResult<Option<Self>> {
        conn.storage().get("mls_psk_bundles", id.as_slice()).await
    }

    async fn count(conn: &mut Self::ConnectionType) -> CryptoKeystoreResult<usize> {
        conn.storage().count("mls_psk_bundles").await
    }

    async fn delete(conn: &mut Self::ConnectionType, ids: &[StringEntityId]) -> CryptoKeystoreResult<()> {
        let storage = conn.storage_mut();
        let ids: Vec<Vec<u8>> = ids.iter().map(StringEntityId::to_bytes).collect();
        storage.delete("mls_psk_bundles", &ids).await
    }
}

impl Entity for MlsPskBundle {
    fn id_raw(&self) -> &[u8] {
        self.psk_id.as_slice()
    }

    fn encrypt(&mut self, cipher: &aes_gcm::Aes256Gcm) -> CryptoKeystoreResult<()> {
        self.psk = Self::encrypt_data(cipher, self.psk.as_slice(), self.aad())?;
        Self::ConnectionType::check_buffer_size(self.psk.len())?;

        Ok(())
    }

    fn decrypt(&mut self, cipher: &aes_gcm::Aes256Gcm) -> CryptoKeystoreResult<()> {
        self.psk = Self::decrypt_data(cipher, self.psk.as_slice(), self.aad())?;

        Ok(())
    }
}
