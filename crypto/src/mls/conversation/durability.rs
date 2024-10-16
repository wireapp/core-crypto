use crate::context::CentralContext;
use crate::mls::{ConversationId, MlsConversation};

impl MlsConversation {
    /// Replaces the MLS group in memory with the one from keystore.
    /// see [crate::durable]
    #[cfg_attr(not(test), tracing::instrument(skip_all))]
    pub async fn drop_and_restore(&mut self, backend: &mls_crypto_provider::TransactionalCryptoProvider) {
        use core_crypto_keystore::CryptoKeystoreMls as _;

        let group_id = self.group.group_id();
        let (parent_id, group) = backend
            .keystore()
            .mls_groups_restore()
            .await
            .map(|mut groups| groups.remove(group_id.as_slice()).unwrap())
            .unwrap();
        let group = MlsConversation::from_serialized_state(group, parent_id).unwrap();
        *self = group;
    }
}

impl CentralContext {
    /// Replaces the MLS group in memory with the one from keystore.
    #[cfg_attr(not(test), tracing::instrument(skip(self), fields (id = BASE64_STANDARD.encode(id))))]
    pub async fn drop_and_restore(&mut self, id: &ConversationId) {
        use core_crypto_keystore::CryptoKeystoreMls as _;

        let (parent_id, group) = self
            .keystore()
            .await
            .unwrap()
            .mls_groups_restore()
            .await
            .map(|mut groups| groups.remove(id.as_slice()).unwrap())
            .unwrap();
        let group = MlsConversation::from_serialized_state(group, parent_id).unwrap();
        self.mls_groups().await.unwrap().insert(id.clone(), group);
    }
}
