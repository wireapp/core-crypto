use core_crypto_keystore::{
    connection::FetchFromDatabase as _,
    entities::{
        MlsPendingMessage, PersistedMlsGroup, PersistedMlsPendingGroup, StoredCredential, StoredE2eiEnrollment,
        StoredEncryptionKeyPair, StoredEpochEncryptionKeypair, StoredHpkePrivateKey, StoredKeypackage, StoredPskBundle,
    },
};

use super::TransactionContext;

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct EntitiesCount {
    pub credential: usize,
    pub encryption_keypair: usize,
    pub epoch_encryption_keypair: usize,
    pub enrollment: usize,
    pub group: usize,
    pub hpke_private_key: usize,
    pub key_package: usize,
    pub pending_group: usize,
    pub pending_messages: usize,
    pub psk_bundle: usize,
}

impl TransactionContext {
    /// Count the entities
    pub async fn count_entities(&self) -> EntitiesCount {
        let keystore = self.keystore().await.unwrap();
        let credential = keystore.count::<StoredCredential>().await.unwrap();
        let encryption_keypair = keystore.count::<StoredEncryptionKeyPair>().await.unwrap();
        let epoch_encryption_keypair = keystore.count::<StoredEpochEncryptionKeypair>().await.unwrap();
        let enrollment = keystore.count::<StoredE2eiEnrollment>().await.unwrap();
        let group = keystore.count::<PersistedMlsGroup>().await.unwrap();
        let hpke_private_key = keystore.count::<StoredHpkePrivateKey>().await.unwrap();
        let key_package = keystore.count::<StoredKeypackage>().await.unwrap();
        let pending_group = keystore.count::<PersistedMlsPendingGroup>().await.unwrap();
        let pending_messages = keystore.count::<MlsPendingMessage>().await.unwrap();
        let psk_bundle = keystore.count::<StoredPskBundle>().await.unwrap();
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
