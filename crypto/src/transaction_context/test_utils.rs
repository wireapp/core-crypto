use core_crypto_keystore::{
    entities::{
        MlsPendingMessage, PersistedMlsGroup, PersistedMlsPendingGroup, StoredCredential, StoredE2eiEnrollment,
        StoredEncryptionKeyPair, StoredEpochEncryptionKeypair, StoredHpkePrivateKey, StoredKeypackage, StoredPskBundle,
    },
    traits::FetchFromDatabase as _,
};

use super::TransactionContext;

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct EntitiesCount {
    pub credential: u32,
    pub encryption_keypair: u32,
    pub epoch_encryption_keypair: u32,
    pub enrollment: u32,
    pub group: u32,
    pub hpke_private_key: u32,
    pub key_package: u32,
    pub pending_group: u32,
    pub pending_messages: u32,
    pub psk_bundle: u32,
}

impl TransactionContext {
    /// Count the entities
    pub async fn count_entities(&self) -> EntitiesCount {
        let inner = self.inner().await.unwrap();
        let credential = inner.transaction.count::<StoredCredential>().await.unwrap();
        let encryption_keypair = inner.transaction.count::<StoredEncryptionKeyPair>().await.unwrap();
        let epoch_encryption_keypair = inner.transaction.count::<StoredEpochEncryptionKeypair>().await.unwrap();
        let enrollment = inner.transaction.count::<StoredE2eiEnrollment>().await.unwrap();
        let group = inner.transaction.count::<PersistedMlsGroup>().await.unwrap();
        let hpke_private_key = inner.transaction.count::<StoredHpkePrivateKey>().await.unwrap();
        let key_package = inner.transaction.count::<StoredKeypackage>().await.unwrap();
        let pending_group = inner.transaction.count::<PersistedMlsPendingGroup>().await.unwrap();
        let pending_messages = inner.transaction.count::<MlsPendingMessage>().await.unwrap();
        let psk_bundle = inner.transaction.count::<StoredPskBundle>().await.unwrap();
        EntitiesCount {
            credential,
            encryption_keypair,
            epoch_encryption_keypair,
            enrollment,
            group,
            hpke_private_key,
            key_package,
            pending_group,
            pending_messages,
            psk_bundle,
        }
    }
}
