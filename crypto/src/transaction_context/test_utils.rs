use core_crypto_keystore::{
    entities::{
        InboxMessage, PersistedMlsGroup, StoredCredential, StoredEncryptionKeyPair, StoredEpochEncryptionKeypair,
        StoredHpkePrivateKey, StoredKeyPackage, StoredPskBundle, WaitingFor,
    },
    traits::FetchFromDatabase as _,
};

use super::TransactionContext;

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct EntitiesCount {
    /// Inbox messages waiting for a proposal
    pub buffered_commits: u32,
    pub credential: u32,
    pub encryption_keypair: u32,
    pub epoch_encryption_keypair: u32,
    pub group: u32,
    pub hpke_private_key: u32,
    pub key_package: u32,
    pub pending_group: u32,
    /// Inbox messages waiting for an epoch or for a pending join
    pub pending_messages: u32,
    pub psk_bundle: u32,
}

impl TransactionContext {
    /// Count the entities
    pub async fn count_entities(&self) -> EntitiesCount {
        let inner = self.inner().unwrap();
        let credential = inner.transaction.count::<StoredCredential>().await.unwrap();
        let encryption_keypair = inner.transaction.count::<StoredEncryptionKeyPair>().await.unwrap();
        let epoch_encryption_keypair = inner.transaction.count::<StoredEpochEncryptionKeypair>().await.unwrap();
        // `mls_groups` now holds both established and pending rows, distinguished by `is_pending`,
        // so `group` and `pending_group` come from one `load_all` rather than two separate counts.
        let all_groups = inner.transaction.load_all::<PersistedMlsGroup>().await.unwrap();
        let group = all_groups.iter().filter(|group| !group.is_pending).count() as u32;
        let pending_group = all_groups.iter().filter(|group| group.is_pending).count() as u32;
        let hpke_private_key = inner.transaction.count::<StoredHpkePrivateKey>().await.unwrap();
        let key_package = inner.transaction.count::<StoredKeyPackage>().await.unwrap();
        let (buffered_commits, pending_messages) =
            count_inbox_messages(&inner.transaction.load_all::<InboxMessage>().await.unwrap());
        let psk_bundle = inner.transaction.count::<StoredPskBundle>().await.unwrap();
        EntitiesCount {
            buffered_commits,
            credential,
            encryption_keypair,
            epoch_encryption_keypair,
            group,
            hpke_private_key,
            key_package,
            pending_group,
            pending_messages,
            psk_bundle,
        }
    }
}

/// Split the inbox into `(buffered_commits, pending_messages)`, the two counts the separate tables used to give.
pub(crate) fn count_inbox_messages(inbox_messages: &[std::sync::Arc<InboxMessage>]) -> (u32, u32) {
    let buffered_commits = inbox_messages
        .iter()
        .filter(|inbox_message| inbox_message.waiting_for == WaitingFor::Proposal)
        .count() as u32;
    (buffered_commits, inbox_messages.len() as u32 - buffered_commits)
}
