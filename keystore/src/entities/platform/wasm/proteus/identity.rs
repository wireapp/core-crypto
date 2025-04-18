use crate::entities::EntityTransactionExt;
use crate::{
    CryptoKeystoreResult, MissingKeyErrorKind,
    connection::{DatabaseConnection, KeystoreDatabaseConnection},
    entities::{Entity, EntityBase, EntityFindParams, ProteusIdentity, StringEntityId},
};

#[async_trait::async_trait(?Send)]
impl EntityBase for ProteusIdentity {
    type ConnectionType = KeystoreDatabaseConnection;
    type AutoGeneratedFields = ();
    const COLLECTION_NAME: &'static str = "proteus_identities";

    fn to_missing_key_err_kind() -> MissingKeyErrorKind {
        MissingKeyErrorKind::ProteusIdentity
    }

    fn to_transaction_entity(self) -> crate::transaction::dynamic_dispatch::Entity {
        crate::transaction::dynamic_dispatch::Entity::ProteusIdentity(self)
    }
}

#[async_trait::async_trait(?Send)]
impl EntityTransactionExt for ProteusIdentity {}

#[async_trait::async_trait(?Send)]
impl Entity for ProteusIdentity {
    fn id_raw(&self) -> &[u8] {
        &[1u8]
    }

    async fn find_all(conn: &mut Self::ConnectionType, _params: EntityFindParams) -> CryptoKeystoreResult<Vec<Self>> {
        let storage = conn.storage();
        storage.get_all(Self::COLLECTION_NAME, None).await
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
        storage.count(Self::COLLECTION_NAME).await
    }

    fn encrypt(&mut self, cipher: &aes_gcm::Aes256Gcm) -> CryptoKeystoreResult<()> {
        self.pk = self.encrypt_data(cipher, self.pk.as_slice())?;
        Self::ConnectionType::check_buffer_size(self.pk.len())?;

        self.sk = self.encrypt_data(cipher, self.sk.as_slice())?;
        Self::ConnectionType::check_buffer_size(self.sk.len())?;

        Ok(())
    }

    fn decrypt(&mut self, cipher: &aes_gcm::Aes256Gcm) -> CryptoKeystoreResult<()> {
        self.pk = self.decrypt_data(cipher, self.pk.as_slice())?;
        self.sk = self.decrypt_data(cipher, self.sk.as_slice())?;

        Ok(())
    }
}
