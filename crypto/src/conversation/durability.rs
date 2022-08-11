use crate::MlsConversation;

impl MlsConversation {
    /// see [crate::durable]
    pub async fn drop_and_restore(&mut self, backend: &mls_crypto_provider::MlsCryptoProvider) {
        use core_crypto_keystore::CryptoKeystoreMls as _;
        use openmls_traits::OpenMlsCryptoProvider as _;

        let group_id = self.group.group_id();
        let group = backend
            .key_store()
            .mls_groups_restore()
            .await
            .map(|mut groups| groups.remove(group_id.as_slice()).unwrap())
            .unwrap();
        let group = MlsConversation::from_serialized_state(group).unwrap();
        *self = group;
    }

    /// see [crate::durable]
    pub async fn hold(&mut self, backend: &mls_crypto_provider::MlsCryptoProvider) -> Vec<u8> {
        use core_crypto_keystore::CryptoKeystoreMls as _;
        use openmls_traits::OpenMlsCryptoProvider as _;

        let group_id = self.group.group_id();
        backend
            .key_store()
            .mls_groups_restore()
            .await
            .map(|mut groups| groups.remove(group_id.as_slice()).unwrap())
            .unwrap()
    }

    /// see [crate::durable]
    pub async fn crush(&mut self, backend: &mls_crypto_provider::MlsCryptoProvider, previous: Vec<u8>) {
        use core_crypto_keystore::CryptoKeystoreMls as _;
        use openmls_traits::OpenMlsCryptoProvider as _;

        let group = MlsConversation::from_serialized_state(previous.clone()).unwrap();
        let group_id = self.group.group_id();
        backend
            .key_store()
            .mls_group_persist(group_id.as_slice(), previous.as_slice())
            .await
            .unwrap();
        *self = group;
    }
}
