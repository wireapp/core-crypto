use crate::mls::{ConversationId, MlsCentral, MlsConversation};

impl MlsConversation {
    /// Replaces the MLS group in memory with the one from keystore.
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
}

impl MlsCentral {
    /// Replaces the MLS group in memory with the one from keystore.
    pub async fn drop_and_restore(&mut self, id: &ConversationId) {
        use core_crypto_keystore::CryptoKeystoreMls as _;
        use openmls_traits::OpenMlsCryptoProvider as _;

        let group = self
            .mls_backend
            .key_store()
            .mls_groups_restore()
            .await
            .map(|mut groups| groups.remove(id.as_slice()).unwrap())
            .unwrap();
        let group = MlsConversation::from_serialized_state(group).unwrap();
        self.mls_groups.insert(id.clone(), group).unwrap();
    }
}
