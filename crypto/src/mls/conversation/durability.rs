use crate::mls::{ConversationId, MlsConversation};
use crate::transaction_context::TransactionContext;

impl MlsConversation {
    /// Replaces the MLS group in memory with the one from keystore.
    /// see [crate::durable]
    pub async fn drop_and_restore(&mut self, backend: &mls_crypto_provider::MlsCryptoProvider) {
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

impl TransactionContext {
    /// Replaces the MLS group in memory with the one from keystore.
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
