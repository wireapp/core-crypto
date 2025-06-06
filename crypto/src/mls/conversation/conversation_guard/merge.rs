//! A MLS group is a distributed object scattered across many parties. We use a Delivery Service
//! to orchestrate those parties. So when we create a commit, a mutable operation, it has to be
//! validated by the Delivery Service. But it might occur that another group member did the
//! exact same thing at the same time. So if we arrive second in this race, we must "rollback" the commit
//! we created and accept ("merge") the other one.
//! A client would
//! * Create a commit
//! * Send the commit to the Delivery Service
//! * When Delivery Service responds
//!     * 200 OK --> use [TransactionContext::commit_accepted] to merge the commit
//!     * 409 CONFLICT --> do nothing. [ConversationGuard::decrypt_message] will restore the proposals not committed
//!     * 5xx --> retry

use openmls::prelude::MlsGroupStateError;

use super::{ConversationGuard, Result};
use crate::{
    MlsError,
    mls::conversation::{ConversationWithMls as _, Error},
    prelude::{MlsProposalRef, Obfuscated},
};

impl ConversationGuard {
    /// Allows to remove a pending (uncommitted) proposal. Use this when backend rejects the proposal
    /// you just sent e.g. if permissions have changed meanwhile.
    ///
    /// **CAUTION**: only use this when you had an explicit response from the Delivery Service
    /// e.g. 403 or 409. Do not use otherwise e.g. 5xx responses, timeout etc..
    ///
    /// # Arguments
    /// * `conversation_id` - the group/conversation id
    /// * `proposal_ref` - unique proposal identifier which is present in [crate::prelude::MlsProposalBundle]
    ///   and returned from all operation creating a proposal
    ///
    /// # Errors
    /// When the conversation is not found or the proposal reference does not identify a proposal
    /// in the local pending proposal store
    pub async fn clear_pending_proposal(&mut self, proposal_ref: MlsProposalRef) -> Result<()> {
        let keystore = self.crypto_provider().await?.keystore();
        let mut conversation = self.conversation_mut().await;
        conversation
            .group
            .remove_pending_proposal(&keystore, &proposal_ref)
            .await
            .map_err(|mls_group_state_error| match mls_group_state_error {
                MlsGroupStateError::PendingProposalNotFound => Error::PendingProposalNotFound(proposal_ref),
                _ => MlsError::wrap("removing pending proposal")(mls_group_state_error).into(),
            })?;
        conversation.persist_group_when_changed(&keystore, true).await?;
        Ok(())
    }

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
        let keystore = self.crypto_provider().await?.keystore();
        let mut conversation = self.conversation_mut().await;
        if conversation.group.pending_commit().is_some() {
            conversation.group.clear_pending_commit();
            conversation.persist_group_when_changed(&keystore, true).await?;
            log::info!(group_id = Obfuscated::from(conversation.id()); "Cleared pending commit.");
            Ok(())
        } else {
            Err(Error::PendingCommitNotFound)
        }
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
    use openmls::prelude::Proposal;

    use crate::test_utils::*;

    use super::*;

    mod clear_pending_proposal {
        use super::*;

        #[apply(all_cred_cipher)]
        pub async fn should_remove_proposal(case: TestContext) {
            let [alice, bob, charlie] = case.sessions().await;
            Box::pin(async move {
                let conversation = case.create_conversation([&alice, &bob]).await;
                let id = conversation.id().clone();
                assert!(alice.pending_proposals(&id).await.is_empty());

                let conversation = conversation.invite_proposal_notify(&charlie).await;
                let add_ref = conversation.latest_proposal_ref().await;

                let conversation = conversation.remove_proposal_notify(&bob).await;
                let remove_ref = conversation.latest_proposal_ref().await;

                let conversation = conversation.update_proposal_notify().await;
                let update_ref = conversation.latest_proposal_ref().await;

                let mut conversation = conversation.guard().await;

                assert_eq!(alice.pending_proposals(&id).await.len(), 3);
                conversation.clear_pending_proposal(add_ref).await.unwrap();
                assert_eq!(alice.pending_proposals(&id).await.len(), 2);
                assert!(
                    !alice
                        .pending_proposals(&id)
                        .await
                        .into_iter()
                        .any(|p| matches!(p.proposal(), Proposal::Add(_)))
                );

                conversation.clear_pending_proposal(remove_ref).await.unwrap();
                assert_eq!(alice.pending_proposals(&id).await.len(), 1);
                assert!(
                    !alice
                        .pending_proposals(&id)
                        .await
                        .into_iter()
                        .any(|p| matches!(p.proposal(), Proposal::Remove(_)))
                );

                conversation.clear_pending_proposal(update_ref).await.unwrap();
                assert!(alice.pending_proposals(&id).await.is_empty());
                assert!(
                    !alice
                        .pending_proposals(&id)
                        .await
                        .into_iter()
                        .any(|p| matches!(p.proposal(), Proposal::Update(_)))
                );
            })
            .await
        }

        #[apply(all_cred_cipher)]
        pub async fn should_fail_when_proposal_ref_not_found(case: TestContext) {
            let [alice] = case.sessions().await;
            Box::pin(async move {
                let conversation = case.create_conversation([&alice]).await;
                let id = conversation.id().clone();
                assert!(alice.pending_proposals(&id).await.is_empty());
                let any_ref = MlsProposalRef::from(vec![0; case.ciphersuite().hash_length()]);
                let clear = conversation.guard().await.clear_pending_proposal(any_ref.clone()).await;
                assert!(matches!(clear.unwrap_err(), Error::PendingProposalNotFound(prop_ref) if prop_ref == any_ref))
            })
            .await
        }

        #[apply(all_cred_cipher)]
        pub async fn should_clean_associated_key_material(case: TestContext) {
            let [session] = case.sessions().await;
            Box::pin(async move {
                let conversation = case.create_conversation([&session]).await;
                let id = conversation.id().clone();
                assert!(session.pending_proposals(&id).await.is_empty());

                let init = session.transaction.count_entities().await;

                let conversation = conversation.update_proposal_notify().await;
                let proposal_ref = conversation.latest_proposal_ref().await;
                assert_eq!(session.pending_proposals(&id).await.len(), 1);

                conversation
                    .guard()
                    .await
                    .clear_pending_proposal(proposal_ref)
                    .await
                    .unwrap();
                assert!(session.pending_proposals(&id).await.is_empty());

                // This whole flow should be idempotent.
                // Here we verify that we are indeed deleting the `EncryptionKeyPair` created
                // for the Update proposal
                let after_clear_proposal = session.transaction.count_entities().await;
                assert_eq!(init, after_clear_proposal);
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
                let id = conversation.id().clone();
                assert!(alice.pending_commit(&id).await.is_none());

                alice.create_unmerged_commit(&id).await;
                assert!(alice.pending_commit(&id).await.is_some());
                conversation.guard().await.clear_pending_commit().await.unwrap();
                assert!(alice.pending_commit(&id).await.is_none());
            })
            .await
        }

        #[apply(all_cred_cipher)]
        pub async fn should_fail_when_pending_commit_absent(case: TestContext) {
            let [alice] = case.sessions().await;
            Box::pin(async move {
                let conversation = case.create_conversation([&alice]).await;
                let id = conversation.id().clone();
                assert!(alice.pending_commit(&id).await.is_none());
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
                let id = conversation.id().clone();
                assert!(session.pending_commit(&id).await.is_none());

                let init = session.transaction.count_entities().await;

                session.create_unmerged_commit(&id).await;
                assert!(session.pending_commit(&id).await.is_some());

                conversation.guard().await.clear_pending_commit().await.unwrap();
                assert!(session.pending_commit(&id).await.is_none());

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
