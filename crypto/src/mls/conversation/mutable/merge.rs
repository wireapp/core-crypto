//! Operations on a conversation guard pertaining to merge commits.
//!
//! An MLS group is a distributed object scattered across many parties. We use a Delivery Service
//! to orchestrate those parties. So when we create a commit, a mutable operation, it has to be
//! validated by the Delivery Service. But it might occur that another group member did the
//! exact same thing at the same time. So if we arrive second in this race, we must "rollback" the commit
//! we created and accept ("merge") the other one.
//!
//! Those three steps — create the commit, send it, merge it — are all performed by
//! [`ConversationMut`] itself; they are not driven by the caller. The caller's part is to supply an
//! [`MlsTransport`][crate::MlsTransport] implementation, whose `send_commit_bundle` reports whether
//! the Delivery Service accepted the commit by returning `Ok` or `Err`. On success the commit is
//! merged locally; on failure the pending commit is discarded. If another member's commit arrives
//! first, decrypting it restores the proposals which were not committed.
//!
//! An MLS group can be merged (aka committed) when it has a pending commit. The latter is a commit
//! we created which has not yet been applied to the conversation. Doing so  will apply all the
//! modifications present in the commit to the ratchet tree and also persist the new group in the
//! keystore, so even if the application crashes, we will be able to restore.
//!
//! This table summarizes when an MLS group can be merged:
//!
//! | can be merged ?   | 0 pend. Commit | 1 pend. Commit |
//! |-------------------|----------------|----------------|
//! | 0 pend. Proposal  | ❌              | ✅              |
//! | 1+ pend. Proposal | ❌              | ✅              |

use core_crypto_keystore::{entities::StoredEncryptionKeyPair, traits::EntityDeleteBorrowed};

use super::{ConversationMut, Result};
use crate::{KeystoreError, OpenMlsError, mls::conversation::Error};

impl ConversationMut {
    /// Apply a pending commit
    pub(super) async fn commit_accepted(&mut self) -> Result<()> {
        let provider = &self.crypto_provider().await?;
        self.mutate_group(async |tx, group, _| {
            // openmls stores here all the encryption keypairs used for update proposals..
            let previous_own_leaf_nodes = group.own_leaf_nodes.clone();

            group
                .merge_pending_commit(provider)
                .await
                .map_err(OpenMlsError::wrap("merging pending commit"))?;

            // ..so if there's any, we clear them after the commit is merged
            for oln in &previous_own_leaf_nodes {
                let ek = oln.encryption_key().as_slice();
                StoredEncryptionKeyPair::delete_borrowed(tx, ek)
                    .map_err(KeystoreError::wrap("deleting stored encryption keypair"))?;
            }

            Ok(())
        })
        .await
    }

    /// Allows to remove a pending commit. Use this when backend rejects the commit
    /// you just sent e.g. if permissions have changed meanwhile.
    ///
    /// Called unconditionally on a mls transport error; clients need to recreate the commits themselves
    /// in that case.
    ///
    /// # Errors
    /// When there is no pending commit
    pub(crate) async fn clear_pending_commit(&mut self) -> Result<()> {
        self.mutate_group(async |_, group, id| {
            if group.pending_commit().is_none() {
                return Err(Error::PendingCommitNotFound);
            }
            group.clear_pending_commit();
            log::info!(group_id = id.to_owned(); "Cleared pending commit.");
            Ok(())
        })
        .await
    }

    /// Clear a pending commit if it exists. Unlike [Self::clear_pending_commit],
    /// don't throw an error if there is none.
    pub(crate) async fn ensure_no_pending_commit(&mut self) -> Result<()> {
        match self.clear_pending_commit().await {
            Err(Error::PendingCommitNotFound) => Ok(()),
            result => result,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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

                conversation.guard().await.commit_accepted().await.unwrap();

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

                conversation.guard().await.commit_accepted().await.unwrap();
                assert!(!conversation.has_pending_proposals().await);
                assert!(!conversation.has_pending_commit().await);
            })
            .await
        }
    }

    mod clear_pending_commit {
        use super::*;

        #[apply(all_cred_cipher)]
        pub async fn should_remove_commit(case: TestContext) {
            let [alice] = case.sessions().await;
            Box::pin(async move {
                let conversation = case.create_conversation([&alice]).await;
                assert!(!conversation.has_pending_commit().await);

                let conversation = conversation.update_unmerged().await.finish();
                assert!(conversation.has_pending_commit().await);
                conversation.guard().await.clear_pending_commit().await.unwrap();
                assert!(!conversation.has_pending_commit().await);
            })
            .await
        }

        #[apply(all_cred_cipher)]
        pub async fn should_fail_when_pending_commit_absent(case: TestContext) {
            let [alice] = case.sessions().await;
            Box::pin(async move {
                let conversation = case.create_conversation([&alice]).await;
                assert!(!conversation.has_pending_commit().await);
                let clear = conversation.guard().await.clear_pending_commit().await;
                assert!(matches!(clear.unwrap_err(), Error::PendingCommitNotFound))
            })
            .await
        }

        #[apply(all_cred_cipher)]
        pub async fn should_clean_associated_key_material(case: TestContext) {
            let [session] = case.sessions().await;
            Box::pin(async move {
                let conversation = case.create_conversation([&session]).await;
                assert!(!conversation.has_pending_commit().await);

                let init = session.transaction.count_entities().await;

                let conversation = conversation.update_unmerged().await.finish();
                assert!(conversation.has_pending_commit().await);

                conversation.guard().await.clear_pending_commit().await.unwrap();
                assert!(!conversation.has_pending_commit().await);

                // This whole flow should be idempotent.
                // Here we verify that we are indeed deleting the `EncryptionKeyPair` created
                // for the Update commit
                let after_clear_commit = session.transaction.count_entities().await;
                assert_eq!(init, after_clear_commit);
            })
            .await
        }
    }
}
