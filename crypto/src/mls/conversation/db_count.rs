use crate::prelude::MlsCentral;
use core_crypto_keystore::entities::{
    E2eiEnrollment, MlsCredential, MlsEncryptionKeyPair, MlsEpochEncryptionKeyPair, MlsHpkePrivateKey, MlsKeyPackage,
    MlsPendingMessage, MlsPskBundle, MlsSignatureKeyPair, PersistedMlsGroup, PersistedMlsPendingGroup,
};

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
    pub signature_keypair: usize,
}

impl MlsCentral {
    pub async fn count_entities(&self) -> EntitiesCount {
        let keystore = self.mls_backend.borrow_keystore();
        let credential = keystore.count::<MlsCredential>().await.unwrap();
        let encryption_keypair = keystore.count::<MlsEncryptionKeyPair>().await.unwrap();
        let epoch_encryption_keypair = keystore.count::<MlsEpochEncryptionKeyPair>().await.unwrap();
        let enrollment = keystore.count::<E2eiEnrollment>().await.unwrap();
        let group = keystore.count::<PersistedMlsGroup>().await.unwrap();
        let hpke_private_key = keystore.count::<MlsHpkePrivateKey>().await.unwrap();
        let key_package = keystore.count::<MlsKeyPackage>().await.unwrap();
        let pending_group = keystore.count::<PersistedMlsPendingGroup>().await.unwrap();
        let pending_messages = keystore.count::<MlsPendingMessage>().await.unwrap();
        let psk_bundle = keystore.count::<MlsPskBundle>().await.unwrap();
        let signature_keypair = keystore.count::<MlsSignatureKeyPair>().await.unwrap();
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
            signature_keypair,
        }
    }
}
