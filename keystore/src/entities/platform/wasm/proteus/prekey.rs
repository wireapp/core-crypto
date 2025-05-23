use crate::entities::EntityTransactionExt;
use crate::{
    CryptoKeystoreResult, MissingKeyErrorKind,
    connection::{DatabaseConnection, KeystoreDatabaseConnection},
    entities::{Entity, EntityBase, EntityFindParams, ProteusPrekey, StringEntityId},
};

#[async_trait::async_trait(?Send)]
impl EntityBase for ProteusPrekey {
    type ConnectionType = KeystoreDatabaseConnection;
    type AutoGeneratedFields = ();
    const COLLECTION_NAME: &'static str = "proteus_prekeys";

    fn to_missing_key_err_kind() -> MissingKeyErrorKind {
        MissingKeyErrorKind::ProteusPrekey
    }

    fn to_transaction_entity(self) -> crate::transaction::dynamic_dispatch::Entity {
        crate::transaction::dynamic_dispatch::Entity::ProteusPrekey(self)
    }
}

#[async_trait::async_trait(?Send)]
impl EntityTransactionExt for ProteusPrekey {}

#[async_trait::async_trait(?Send)]
impl Entity for ProteusPrekey {
    fn id_raw(&self) -> &[u8] {
        self.id_bytes()
    }

    async fn find_all(conn: &mut Self::ConnectionType, params: EntityFindParams) -> CryptoKeystoreResult<Vec<Self>> {
        let storage = conn.storage();
        storage.get_all(Self::COLLECTION_NAME, Some(params)).await
    }

    async fn find_one(
        conn: &mut Self::ConnectionType,
        id: &StringEntityId,
    ) -> crate::CryptoKeystoreResult<Option<Self>> {
        let storage = conn.storage();
        storage.get(Self::COLLECTION_NAME, id.as_slice()).await
    }

    async fn count(conn: &mut Self::ConnectionType) -> crate::CryptoKeystoreResult<usize> {
        let storage = conn.storage();
        storage.count(Self::COLLECTION_NAME).await
    }

    fn encrypt(&mut self, cipher: &aes_gcm::Aes256Gcm) -> CryptoKeystoreResult<()> {
        self.prekey = self.encrypt_data(cipher, self.prekey.as_slice())?;
        Self::ConnectionType::check_buffer_size(self.prekey.len())?;

        Ok(())
    }

    fn decrypt(&mut self, cipher: &aes_gcm::Aes256Gcm) -> CryptoKeystoreResult<()> {
        self.prekey = self.decrypt_data(cipher, self.prekey.as_slice())?;

        Ok(())
    }
}
