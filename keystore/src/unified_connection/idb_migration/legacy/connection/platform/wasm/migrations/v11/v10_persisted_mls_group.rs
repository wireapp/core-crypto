use async_trait::async_trait;

use crate::{
    CryptoKeystoreResult,
    entities::PersistedMlsGroup,
    unified_connection::idb_migration::legacy::{
        connection::KeystoreDatabaseConnection,
        traits::{DecryptData, Decryptable, Decrypting, Entity, EntityBase},
    },
};

/// Entity representing a persisted `MlsGroup`
#[derive(core_crypto_macros::Debug)]
#[sensitive]
pub(crate) struct V10PersistedMlsGroup {
    id: Vec<u8>,
    state: Vec<u8>,
    parent_id: Option<Vec<u8>>,
}

impl From<V10PersistedMlsGroup> for PersistedMlsGroup {
    fn from(V10PersistedMlsGroup { id, state, parent_id }: V10PersistedMlsGroup) -> Self {
        PersistedMlsGroup { id, state, parent_id }
    }
}

impl EntityBase for V10PersistedMlsGroup {
    type ConnectionType = KeystoreDatabaseConnection;
    const COLLECTION_NAME: &'static str = "mls_groups";
    fn to_transaction_entity(self) -> crate::transaction::dynamic_dispatch::Entity {
        panic!("this entity should never be part of a transaction")
    }
}

impl crate::traits::PrimaryKey for V10PersistedMlsGroup {
    type PrimaryKey = Vec<u8>;
    fn primary_key(&self) -> Self::PrimaryKey {
        self.id.clone()
    }
}

#[async_trait(?Send)]
impl Entity for V10PersistedMlsGroup {
    async fn get(conn: &mut Self::ConnectionType, key: &Self::PrimaryKey) -> CryptoKeystoreResult<Option<Self>> {
        conn.storage().get::<Self>(key).await
    }

    async fn count(conn: &mut Self::ConnectionType) -> CryptoKeystoreResult<u32> {
        conn.storage().count::<Self>().await
    }

    async fn load_all(conn: &mut Self::ConnectionType) -> CryptoKeystoreResult<Vec<Self>> {
        conn.storage().get_all().await
    }
}

#[derive(serde::Deserialize)]
pub(crate) struct V10PersistedMlsGroupDecrypt {
    id: Vec<u8>,
    parent_id: Option<Vec<u8>>,
    state: Vec<u8>,
}

impl Decrypting<'static> for V10PersistedMlsGroupDecrypt {
    type DecryptedForm = V10PersistedMlsGroup;
    fn decrypt(self, cipher: &aes_gcm::Aes256Gcm) -> crate::CryptoKeystoreResult<V10PersistedMlsGroup> {
        Ok(V10PersistedMlsGroup {
            parent_id: self
                .parent_id
                .as_ref()
                .map(|parent_id| <V10PersistedMlsGroup as DecryptData>::decrypt_data(cipher, &self.id, parent_id))
                .transpose()?,
            state: <V10PersistedMlsGroup as DecryptData>::decrypt_data(cipher, &self.id, &self.state)?,
            id: self.id,
        })
    }
}

impl Decryptable<'static> for V10PersistedMlsGroup {
    type DecryptableFrom = V10PersistedMlsGroupDecrypt;
}
