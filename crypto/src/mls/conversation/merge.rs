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

use core_crypto_keystore::{entities::StoredEncryptionKeyPair, traits::CryptoTransaction as _};
use openmls_traits::OpenMlsCryptoProvider;

use super::Result;
use crate::{MlsError, mls::MlsConversation, mls_provider::MlsCryptoProvider};

/// Abstraction over a MLS group capable of merging a commit
impl MlsConversation {
    pub(crate) async fn commit_accepted(&mut self, provider: &MlsCryptoProvider) -> Result<()> {
        // openmls stores here all the encryption keypairs used for update proposals..
        let previous_own_leaf_nodes = self.group.own_leaf_nodes.clone();

        self.group
            .merge_pending_commit(provider)
            .await
            .map_err(MlsError::wrap("merging pending commit"))?;

        // ..so if there's any, we clear them after the commit is merged
        for oln in &previous_own_leaf_nodes {
            let ek = oln.encryption_key().as_slice();
            let _ = provider
                .key_store()
                .remove_borrowed::<StoredEncryptionKeyPair>(ek)
                .await;
        }

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
                    .conversation_mut(async |conversation| {
                        conversation
                            .commit_accepted(&alice.session().await.crypto_provider)
                            .await
                    })
                    .await
                    .unwrap();

                assert_eq!(conversation.member_count().await, 2);
                assert!(conversation.is_functional_and_contains([&alice, &bob]).await);
            })
            .await
        }

        #[apply(all_cred_cipher)]
        async fn should_clear_pending_commit_and_proposals(case: TestContext) {
            let [alice, bob] = case.sessions().await;
            Box::pin(async move {
                let commit = case
                    .create_conversation([&alice, &bob])
                    .await
                    .remove_proposal_notify(&bob)
                    .await
                    .update_unmerged()
                    .await;

                let conversation = commit.conversation();

                assert!(conversation.has_pending_proposals().await);
                assert!(conversation.has_pending_commit().await);

                conversation
                    .guard()
                    .await
                    .conversation_mut(async |conversation| {
                        conversation
                            .commit_accepted(&alice.session().await.crypto_provider)
                            .await
                    })
                    .await
                    .unwrap();
                assert!(!conversation.has_pending_proposals().await);
                assert!(!conversation.has_pending_commit().await);
            })
            .await
        }
    }
}
