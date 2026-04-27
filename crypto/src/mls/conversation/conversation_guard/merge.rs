//! A MLS group is a distributed object scattered across many parties. We use a Delivery Service
//! to orchestrate those parties. So when we create a commit, a mutable operation, it has to be
//! validated by the Delivery Service. But it might occur that another group member did the
//! exact same thing at the same time. So if we arrive second in this race, we must "rollback" the commit
//! we created and accept ("merge") the other one.
//! A client would
//! * Create a commit
//! * Send the commit to the Delivery Service
//! * When Delivery Service responds
//!     * 200 OK --> use [MlsConversation::commit_accepted][super::MlsConversation::commit_accepted] to merge the commit
//!     * 409 CONFLICT --> do nothing. [ConversationGuard::decrypt_message] will restore the proposals not committed
//!     * 5xx --> retry

use super::{ConversationGuard, Result};
use crate::mls::conversation::Error;

impl ConversationGuard {
    /// Allows to remove a pending commit. Use this when backend rejects the commit
    /// you just sent e.g. if permissions have changed meanwhile.
    ///
    /// **CAUTION**: only use this when you had an explicit response from the Delivery Service
    /// e.g. 403. Do not use otherwise e.g. 5xx responses, timeout etc..
    /// **DO NOT** use when Delivery Service responds 409, pending state will be renewed
    /// in [ConversationGuard::decrypt_message]
    ///
    ///
    /// # Errors
    /// When there is no pending commit
    pub(crate) async fn clear_pending_commit(&mut self) -> Result<()> {
        let database = self.database().await?;
        self.conversation_mut(async |conversation| {
            if conversation.group.pending_commit().is_some() {
                conversation.group.clear_pending_commit();
                conversation.persist_group_when_changed(&database, true).await?;
                log::info!(group_id = conversation.id(); "Cleared pending commit.");
                Ok(())
            } else {
                Err(Error::PendingCommitNotFound)
            }
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
