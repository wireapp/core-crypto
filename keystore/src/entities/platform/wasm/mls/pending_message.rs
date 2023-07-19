use crate::{
    connection::KeystoreDatabaseConnection,
    entities::{Entity, EntityBase, EntityFindParams, MlsPendingMessage, StringEntityId},
    CryptoKeystoreResult, MissingKeyErrorKind,
};

#[cfg_attr(target_family = "wasm", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_family = "wasm"), async_trait::async_trait)]
impl EntityBase for MlsPendingMessage {
    type ConnectionType = KeystoreDatabaseConnection;
    type AutoGeneratedFields = ();

    fn to_missing_key_err_kind() -> MissingKeyErrorKind {
        MissingKeyErrorKind::MlsPendingMessages
    }

    async fn find_all(conn: &mut Self::ConnectionType, params: EntityFindParams) -> CryptoKeystoreResult<Vec<Self>> {
        let storage = conn.storage();
        storage.get_all("mls_pending_messages", Some(params)).await
    }

    async fn save(&self, conn: &mut Self::ConnectionType) -> crate::CryptoKeystoreResult<()> {
        let storage = conn.storage_mut();

        storage.save("mls_pending_messages", &mut [self.clone()]).await?;

        Ok(())
    }

    async fn find_one(
        conn: &mut Self::ConnectionType,
        id: &StringEntityId,
    ) -> crate::CryptoKeystoreResult<Option<Self>> {
        conn.storage().get("mls_pending_messages", id.as_slice()).await
    }

    async fn find_many(
        conn: &mut Self::ConnectionType,
        _ids: &[StringEntityId],
    ) -> crate::CryptoKeystoreResult<Vec<Self>> {
        // Plot twist: we always select ALL the persisted groups. Unsure if we want to make it a real API with selection
        conn.storage().get_all("mls_pending_messages", None).await
    }

    async fn count(conn: &mut Self::ConnectionType) -> crate::CryptoKeystoreResult<usize> {
        conn.storage().count("mls_pending_messages").await
    }

    async fn delete(conn: &mut Self::ConnectionType, ids: &[StringEntityId]) -> crate::CryptoKeystoreResult<()> {
        let ids: Vec<Vec<u8>> = ids.iter().map(StringEntityId::to_bytes).collect();
        let _ = conn.storage_mut().delete("mls_pending_messages", &ids).await?;
        Ok(())
    }
}

impl Entity for MlsPendingMessage {
    fn id_raw(&self) -> &[u8] {
        self.id.as_slice()
    }

    fn id(&self) -> CryptoKeystoreResult<wasm_bindgen::JsValue> {
        Ok(js_sys::Uint8Array::from(self.id.as_slice()).into())
    }

    fn aad(&self) -> &[u8] {
        self.id.as_slice()
    }

    fn encrypt(&mut self, cipher: &aes_gcm::Aes256Gcm) -> CryptoKeystoreResult<()> {
        self.message = Self::encrypt_data(cipher, self.message.as_slice(), self.aad())?;

        Ok(())
    }

    fn decrypt(&mut self, cipher: &aes_gcm::Aes256Gcm) -> CryptoKeystoreResult<()> {
        self.message = Self::decrypt_data(cipher, self.message.as_slice(), self.aad())?;

        Ok(())
    }
}
