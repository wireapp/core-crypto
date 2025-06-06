//! A MLS group can be merged (aka committed) when it has a pending commit. The latter is a commit
//! we created which is still waiting to be "committed". By doing so, we will apply all the
//! modifications present in the commit to the ratchet tree and also persist the new group in the
//! keystore. Like this, even if the application crashes we will be able to restore.
//!
//! This table summarizes when a MLS group can be merged:
//!
//! | can be merged ?   | 0 pend. Commit | 1 pend. Commit |
//! |-------------------|----------------|----------------|
//! | 0 pend. Proposal  | ❌              | ✅              |
//! | 1+ pend. Proposal | ❌              | ✅              |
//!

use core_crypto_keystore::entities::MlsEncryptionKeyPair;
use openmls_traits::OpenMlsCryptoProvider;

use mls_crypto_provider::MlsCryptoProvider;

use super::Result;
use crate::{MlsError, mls::MlsConversation, prelude::Session};

/// Abstraction over a MLS group capable of merging a commit
impl MlsConversation {
    /// see [TransactionContext::commit_accepted]
    #[cfg_attr(test, crate::durable)]
    pub(crate) async fn commit_accepted(&mut self, client: &Session, backend: &MlsCryptoProvider) -> Result<()> {
        // openmls stores here all the encryption keypairs used for update proposals..
        let previous_own_leaf_nodes = self.group.own_leaf_nodes.clone();

        self.group
            .merge_pending_commit(backend)
            .await
            .map_err(MlsError::wrap("merging pending commit"))?;
        self.persist_group_when_changed(&backend.keystore(), false).await?;

        // ..so if there's any, we clear them after the commit is merged
        for oln in &previous_own_leaf_nodes {
            let ek = oln.encryption_key().as_slice();
            let _ = backend.key_store().remove::<MlsEncryptionKeyPair, _>(ek).await;
        }

        client
            .notify_epoch_changed(self.id.clone(), self.group.epoch().as_u64())
            .await;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::test_utils::*;

    mod commit_accepted {
        use super::*;

        #[apply(all_cred_cipher)]
        async fn should_apply_pending_commit(case: TestContext) {
            let [alice, bob] = case.sessions().await;
            Box::pin(async move {
                let conversation = case.create_conversation([&alice, &bob]).await;
                let commit_guard = conversation.update_unmerged().await.notify_member(&bob).await;
                let conversation = commit_guard.conversation();

                assert!(conversation.has_pending_commit().await);

                conversation
                    .guard()
                    .await
                    .conversation_mut()
                    .await
                    .commit_accepted(
                        &alice.transaction.session().await.unwrap(),
                        &alice.session.crypto_provider,
                    )
                    .await
                    .unwrap();

                assert_eq!(conversation.member_count().await, 2);
                assert!(conversation.is_functional_and_contains([&alice, &bob]).await);
            })
            .await
        }

        #[apply(all_cred_cipher)]
        async fn should_clear_pending_commit_and_proposals(case: TestContext) {
            let [alice] = case.sessions().await;
            Box::pin(async move {
                let commit = case
                    .create_conversation([&alice])
                    .await
                    .update_proposal_notify()
                    .await
                    .update_unmerged()
                    .await;

                let conversation = commit.conversation();

                assert!(conversation.has_pending_proposals().await);
                assert!(conversation.has_pending_commit().await);

                conversation
                    .guard()
                    .await
                    .conversation_mut()
                    .await
                    .commit_accepted(
                        &alice.transaction.session().await.unwrap(),
                        &alice.session.crypto_provider,
                    )
                    .await
                    .unwrap();
                assert!(!conversation.has_pending_proposals().await);
                assert!(!conversation.has_pending_commit().await);
            })
            .await
        }

        #[apply(all_cred_cipher)]
        async fn should_clean_associated_key_material(case: TestContext) {
            let [alice] = case.sessions().await;
            Box::pin(async move {
                let conversation = case.create_conversation([&alice]).await;
                let initial_count = alice.transaction.count_entities().await;

                let conversation = conversation.update_proposal_notify().await;
                let post_proposal_count = alice.transaction.count_entities().await;
                assert_eq!(
                    post_proposal_count.encryption_keypair,
                    initial_count.encryption_keypair + 1
                );

                conversation.commit_pending_proposals_notify().await;

                let final_count = alice.transaction.count_entities().await;
                assert_eq!(initial_count, final_count);
            })
            .await
        }
    }
}
