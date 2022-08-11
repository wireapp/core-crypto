#![cfg(test)]

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
}
