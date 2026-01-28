use core_crypto_keystore::Database;

use crate::mls::MlsConversation;

impl MlsConversation {
    /// Replaces the MLS group in memory with the one from keystore.
    /// see [crate::durable]
    pub async fn drop_and_restore(&mut self, database: &Database) {
        use core_crypto_keystore::CryptoKeystoreMls as _;

        let group_id = self.group.group_id();
        let (parent_id, group) = database
            .mls_groups_restore()
            .await
            .map(|mut groups| groups.remove(group_id.as_slice()).unwrap())
            .unwrap();
        let group = MlsConversation::from_serialized_state(group, parent_id.map(Into::into)).unwrap();
        *self = group;
    }
}
