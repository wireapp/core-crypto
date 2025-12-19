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
