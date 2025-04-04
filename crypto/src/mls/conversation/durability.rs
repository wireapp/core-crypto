use crate::mls::MlsConversation;

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
