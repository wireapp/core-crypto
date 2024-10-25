use crate::{
    connection::KeystoreDatabaseConnection,
    entities::{Entity, EntityBase, EntityFindParams, EntityTransactionExt, MlsPendingMessage, StringEntityId},
    CryptoKeystoreResult, MissingKeyErrorKind,
};

#[cfg_attr(target_family = "wasm", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_family = "wasm"), async_trait::async_trait)]
impl EntityBase for MlsPendingMessage {
    type ConnectionType = KeystoreDatabaseConnection;
    type AutoGeneratedFields = ();
    const COLLECTION_NAME: &'static str = "mls_pending_messages";

    fn to_missing_key_err_kind() -> MissingKeyErrorKind {
        MissingKeyErrorKind::MlsPendingMessages
    }

    fn to_transaction_entity(self) -> crate::transaction::dynamic_dispatch::Entity {
        crate::transaction::dynamic_dispatch::Entity::MlsPendingMessage(self)
    }

    async fn find_all(conn: &mut Self::ConnectionType, params: EntityFindParams) -> CryptoKeystoreResult<Vec<Self>> {
        let storage = conn.storage();
        storage.get_all(Self::COLLECTION_NAME, Some(params)).await
    }

    async fn find_one(
        conn: &mut Self::ConnectionType,
        id: &StringEntityId,
    ) -> crate::CryptoKeystoreResult<Option<Self>> {
        conn.storage().get(Self::COLLECTION_NAME, id.as_slice()).await
    }

    async fn find_many(
        conn: &mut Self::ConnectionType,
        _ids: &[StringEntityId],
    ) -> crate::CryptoKeystoreResult<Vec<Self>> {
        // Plot twist: we always select ALL the persisted groups. Unsure if we want to make it a real API with selection
        conn.storage().get_all(Self::COLLECTION_NAME, None).await
    }

    async fn count(conn: &mut Self::ConnectionType) -> crate::CryptoKeystoreResult<usize> {
        conn.storage().count(Self::COLLECTION_NAME).await
    }
}

#[cfg_attr(target_family = "wasm", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_family = "wasm"), async_trait::async_trait)]
impl EntityTransactionExt for MlsPendingMessage {}

impl Entity for MlsPendingMessage {
    fn id_raw(&self) -> &[u8] {
        self.foreign_id.as_slice()
    }

    fn id(&self) -> CryptoKeystoreResult<wasm_bindgen::JsValue> {
        Ok(js_sys::Uint8Array::from(self.foreign_id.as_slice()).into())
    }

    fn merge_key(&self) -> Vec<u8> {
        // Use this as a merge key because the `id` is not used as a primary key
        // but  as a foreign key: it's the ID of the PersistedMlsPendingGroup.
        self.message.clone()
    }

    fn encrypt(&mut self, cipher: &aes_gcm::Aes256Gcm) -> CryptoKeystoreResult<()> {
        self.message = self.encrypt_data(cipher, self.message.as_slice())?;

        Ok(())
    }

    fn decrypt(&mut self, cipher: &aes_gcm::Aes256Gcm) -> CryptoKeystoreResult<()> {
        self.message = self.decrypt_data(cipher, self.message.as_slice())?;

        Ok(())
    }
}
