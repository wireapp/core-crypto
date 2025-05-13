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
    use wasm_bindgen_test::*;

    use crate::{prelude::*, test_utils::*};

    wasm_bindgen_test_configure!(run_in_browser);
    use super::Error;

    mod add {
        use super::*;

        #[apply(all_cred_cipher)]
        #[wasm_bindgen_test]
        pub async fn should_add_member(case: TestContext) {
            let [alice_central, bob_central] = case.sessions().await;
            Box::pin(async move {
                let id = conversation_id();
                alice_central
                    .transaction
                    .new_conversation(&id, case.credential_type, case.cfg.clone())
                    .await
                    .unwrap();
                let bob_kp = bob_central.get_one_key_package(&case).await;
                alice_central.transaction.new_add_proposal(&id, bob_kp).await.unwrap();
                alice_central
                    .transaction
                    .conversation(&id)
                    .await
                    .unwrap()
                    .commit_pending_proposals()
                    .await
                    .unwrap();
                let welcome = alice_central.mls_transport.latest_welcome_message().await;
                assert_eq!(alice_central.get_conversation_unchecked(&id).await.members().len(), 2);
                let new_id = bob_central
                    .transaction
                    .process_welcome_message(welcome.into(), case.custom_cfg())
                    .await
                    .unwrap()
                    .id;
                assert_eq!(id, new_id);
                assert!(bob_central.try_talk_to(&id, &alice_central).await.is_ok());
            })
            .await
        }
    }

    mod update {
        use super::*;
        use itertools::Itertools;

        #[apply(all_cred_cipher)]
        #[wasm_bindgen_test]
        pub async fn should_update_hpke_key(case: TestContext) {
            let [session] = case.sessions().await;
            let id = conversation_id();
            session
                .transaction
                .new_conversation(&id, case.credential_type, case.cfg.clone())
                .await
                .unwrap();
            let before = session
                .get_conversation_unchecked(&id)
                .await
                .encryption_keys()
                .find_or_first(|_| true)
                .unwrap();
            session.transaction.new_update_proposal(&id).await.unwrap();
            session
                .transaction
                .conversation(&id)
                .await
                .unwrap()
                .commit_pending_proposals()
                .await
                .unwrap();
            let after = session
                .get_conversation_unchecked(&id)
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
        #[wasm_bindgen_test]
        pub async fn should_remove_member(case: TestContext) {
            let [alice_central, bob_central] = case.sessions().await;
            Box::pin(async move {
                let id = conversation_id();
                alice_central
                    .transaction
                    .new_conversation(&id, case.credential_type, case.cfg.clone())
                    .await
                    .unwrap();
                alice_central.invite_all(&case, &id, [&bob_central]).await.unwrap();
                assert_eq!(alice_central.get_conversation_unchecked(&id).await.members().len(), 2);
                assert_eq!(bob_central.get_conversation_unchecked(&id).await.members().len(), 2);

                let remove_proposal = alice_central
                    .transaction
                    .new_remove_proposal(&id, bob_central.get_client_id().await)
                    .await
                    .unwrap();
                bob_central
                    .transaction
                    .conversation(&id)
                    .await
                    .unwrap()
                    .decrypt_message(remove_proposal.proposal.to_bytes().unwrap())
                    .await
                    .unwrap();
                alice_central
                    .transaction
                    .conversation(&id)
                    .await
                    .unwrap()
                    .commit_pending_proposals()
                    .await
                    .unwrap();
                assert_eq!(alice_central.get_conversation_unchecked(&id).await.members().len(), 1);

                let commit = alice_central.mls_transport.latest_commit().await;
                bob_central
                    .transaction
                    .conversation(&id)
                    .await
                    .unwrap()
                    .decrypt_message(commit.to_bytes().unwrap())
                    .await
                    .unwrap();
                assert!(matches!(
                    bob_central.transaction.conversation(&id).await.unwrap_err(),
                    Error::Leaf(LeafError::ConversationNotFound(conv_id)) if conv_id == id
                ));
            })
            .await
        }

        #[apply(all_cred_cipher)]
        #[wasm_bindgen_test]
        pub async fn should_fail_when_unknown_client(case: TestContext) {
            let [alice_central] = case.sessions().await;
            Box::pin(async move {
                let id = conversation_id();
                alice_central
                    .transaction
                    .new_conversation(&id, case.credential_type, case.cfg.clone())
                    .await
                    .unwrap();

                let remove_proposal = alice_central
                    .transaction
                    .new_remove_proposal(&id, b"unknown"[..].into())
                    .await;
                assert!(matches!(
                    remove_proposal.unwrap_err(),
                    Error::ClientNotFound(client_id) if client_id == b"unknown"[..].into()
                ));
            })
            .await
        }
    }
}
