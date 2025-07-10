use openmls::prelude::KeyPackage;

use super::{Error, Result};
use crate::{
    RecursiveError,
    prelude::{ClientId, ConversationId, MlsProposal, MlsProposalBundle},
    transaction_context::TransactionContext,
};

impl TransactionContext {
    /// Creates a new Add proposal
    #[cfg_attr(test, crate::idempotent)]
    pub async fn new_add_proposal(&self, id: &ConversationId, key_package: KeyPackage) -> Result<MlsProposalBundle> {
        self.new_proposal(id, MlsProposal::Add(key_package)).await
    }

    /// Creates a new Add proposal
    #[cfg_attr(test, crate::idempotent)]
    pub async fn new_remove_proposal(&self, id: &ConversationId, client_id: ClientId) -> Result<MlsProposalBundle> {
        self.new_proposal(id, MlsProposal::Remove(client_id)).await
    }

    /// Creates a new Add proposal
    #[cfg_attr(test, crate::dispotent)]
    pub async fn new_update_proposal(&self, id: &ConversationId) -> Result<MlsProposalBundle> {
        self.new_proposal(id, MlsProposal::Update).await
    }

    /// Creates a new proposal within a group
    ///
    /// # Arguments
    /// * `conversation` - the group/conversation id
    /// * `proposal` - the proposal do be added in the group
    ///
    /// # Return type
    /// A [MlsProposalBundle] with the proposal in a Mls message and a reference to that proposal in order to rollback it if required
    ///
    /// # Errors
    /// If the conversation is not found, an error will be returned. Errors from OpenMls can be
    /// returned as well, when for example there's a commit pending to be merged
    async fn new_proposal(&self, id: &ConversationId, proposal: MlsProposal) -> Result<MlsProposalBundle> {
        let mut conversation = self.conversation(id).await?;
        let mut conversation = conversation.conversation_mut().await;
        let client = &self.session().await?;
        let backend = &self.mls_provider().await?;
        let proposal = match proposal {
            MlsProposal::Add(key_package) => conversation
                .propose_add_member(client, backend, key_package.into())
                .await
                .map_err(RecursiveError::mls_conversation("proposing to add member"))?,
            MlsProposal::Update => conversation
                .propose_self_update(client, backend)
                .await
                .map_err(RecursiveError::mls_conversation("proposing self update"))?,
            MlsProposal::Remove(client_id) => {
                let index = conversation
                    .group
                    .members()
                    .find(|kp| kp.credential.identity() == client_id.as_slice())
                    .ok_or(Error::ClientNotFound(client_id))
                    .map(|kp| kp.index)?;
                (*conversation)
                    .propose_remove_member(client, backend, index)
                    .await
                    .map_err(RecursiveError::mls_conversation("proposing to remove member"))?
            }
        };
        Ok(proposal)
    }
}

#[cfg(test)]
mod tests {
    use crate::mls::conversation::ConversationWithMls as _;
    use crate::{prelude::*, test_utils::*};

    use super::Error;

    mod add {
        use super::*;

        #[apply(all_cred_cipher)]
        pub async fn should_add_member(case: TestContext) {
            let [alice, bob] = case.sessions().await;
            Box::pin(async move {
                let conversation = case
                    .create_conversation([&alice])
                    .await
                    .invite_proposal_notify(&bob)
                    .await
                    .commit_pending_proposals_notify()
                    .await;
                assert_eq!(conversation.member_count().await, 2);
                assert!(conversation.is_functional_and_contains([&alice, &bob]).await);
            })
            .await
        }
    }

    mod update {
        use super::*;
        use itertools::Itertools;

        #[apply(all_cred_cipher)]
        pub async fn should_update_hpke_key(case: TestContext) {
            let [session] = case.sessions().await;
            let conversation = case.create_conversation([&session]).await;
            let conversation_guard = conversation.guard().await;
            let before = conversation_guard
                .conversation()
                .await
                .encryption_keys()
                .find_or_first(|_| true)
                .unwrap();
            conversation
                .update_proposal_notify()
                .await
                .commit_pending_proposals_notify()
                .await;
            let after = conversation_guard
                .conversation()
                .await
                .encryption_keys()
                .find_or_first(|_| true)
                .unwrap();
            assert_ne!(before, after)
        }
    }

    mod remove {
        use super::*;

        #[apply(all_cred_cipher)]
        pub async fn should_remove_member(case: TestContext) {
            let [alice, bob] = case.sessions().await;
            Box::pin(async move {
                let conversation = case.create_conversation([&alice, &bob]).await;
                let id = conversation.id().clone();
                assert_eq!(conversation.member_count().await, 2);

                let conversation = conversation
                    .remove_proposal_notify(&bob)
                    .await
                    .commit_pending_proposals_notify()
                    .await;

                assert_eq!(conversation.member_count().await, 1);

                assert!(matches!(
                    bob.transaction.conversation(&id).await.unwrap_err(),
                    Error::Leaf(LeafError::ConversationNotFound(conv_id)) if conv_id == id
                ));
            })
            .await
        }

        #[apply(all_cred_cipher)]
        pub async fn should_fail_when_unknown_client(case: TestContext) {
            let [alice] = case.sessions().await;
            Box::pin(async move {
                let conversation = case.create_conversation([&alice]).await;
                let id = conversation.id().clone();

                let remove_proposal = alice.transaction.new_remove_proposal(&id, b"unknown"[..].into()).await;
                assert!(matches!(
                    remove_proposal.unwrap_err(),
                    Error::ClientNotFound(client_id) if client_id == b"unknown"[..].into()
                ));
            })
            .await
        }
    }
}
