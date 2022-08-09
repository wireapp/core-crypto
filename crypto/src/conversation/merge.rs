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

use openmls::prelude::MlsGroupStateError;

use mls_crypto_provider::MlsCryptoProvider;

use crate::prelude::MlsProposalRef;
use crate::{ConversationId, CryptoError, CryptoResult, MlsCentral, MlsConversation, MlsError};

/// Abstraction over a MLS group capable of merging a commit
impl MlsConversation {
    /// see [MlsCentral::commit_accepted]
    pub async fn commit_accepted(&mut self, backend: &MlsCryptoProvider) -> CryptoResult<()> {
        self.group.merge_pending_commit().map_err(MlsError::from)?;
        self.persist_group_when_changed(backend, false).await
    }

    /// see [MlsCentral::clear_pending_proposal]
    pub async fn clear_pending_proposal(
        &mut self,
        proposal_ref: MlsProposalRef,
        backend: &MlsCryptoProvider,
    ) -> CryptoResult<()> {
        self.group.clear_pending_proposal(*proposal_ref).map_err(|e| match e {
            MlsGroupStateError::PendingProposalNotFound => CryptoError::PendingProposalNotFound(proposal_ref),
            _ => CryptoError::from(MlsError::from(e)),
        })?;
        self.persist_group_when_changed(backend, false).await
    }

    /// see [MlsCentral::clear_pending_commit]
    pub async fn clear_pending_commit(&mut self, backend: &MlsCryptoProvider) -> CryptoResult<()> {
        if self.group.pending_commit().is_some() {
            self.group.clear_pending_commit();
            self.persist_group_when_changed(backend, false).await
        } else {
            Err(CryptoError::PendingCommitNotFound)
        }
    }
}

/// A MLS group is a distributed object scattered across many parties. We use a Delivery Service
/// to orchestrate those parties. So when we create a commit, a mutable operation, it has to be
/// validated by the Delivery Service. But it might occur that another group member did the
/// exact same thing at the same time. So if we arrive second in this race, we must "rollback" the commit
/// we created and accept ("merge") the other one.
/// A client would
/// * Create a commit
/// * Send the commit to the Delivery Service
/// * When Delivery Service responds
///     * 200 OK --> use [MlsCentral::commit_accepted] to merge the commit
///     * 409 CONFLICT --> do nothing. [MlsCentral::decrypt_message] will restore the proposals not committed
///     * 5xx --> retry
impl MlsCentral {
    /// The commit we created has been accepted by the Delivery Service. Hence it is guaranteed
    /// to be used for the new epoch.
    /// We can now safely "merge" it (effectively apply the commit to the group) and update it
    /// in the keystore. The previous can be discarded to respect Forward Secrecy.
    pub async fn commit_accepted(&mut self, conversation_id: &ConversationId) -> CryptoResult<()> {
        Self::get_conversation_mut(&mut self.mls_groups, conversation_id)?
            .commit_accepted(&self.mls_backend)
            .await
    }

    /// Allows to remove a pending (uncommitted) proposal. Use this when backend rejects the proposal
    /// you just sent e.g. if permissions have changed meanwhile.
    ///
    /// **CAUTION**: only use this when you had an explicit response from the Delivery Service
    /// e.g. 403 or 409. Do not use otherwise e.g. 5xx responses, timeout etc..
    ///
    /// # Arguments
    /// * `conversation_id` - the group/conversation id
    /// * `proposal_ref` - unique proposal identifier which is present in [MlsProposalBundle] and
    /// returned from all operation creating a proposal
    ///
    /// # Errors
    /// When the conversation is not found or the proposal reference does not identify a proposal
    /// in the local pending proposal store
    pub async fn clear_pending_proposal(
        &mut self,
        conversation_id: &ConversationId,
        proposal_ref: Vec<u8>,
    ) -> CryptoResult<()> {
        Self::get_conversation_mut(&mut self.mls_groups, conversation_id)?
            .clear_pending_proposal(proposal_ref.try_into()?, &self.mls_backend)
            .await
    }

    /// Allows to remove a pending commit. Use this when backend rejects the commit
    /// you just sent e.g. if permissions have changed meanwhile.
    ///
    /// **CAUTION**: only use this when you had an explicit response from the Delivery Service
    /// e.g. 403. Do not use otherwise e.g. 5xx responses, timeout etc..
    /// **DO NOT** use when Delivery Service responds 409, pending state will be renewed
    /// in [MlsCentral::decrypt_message]
    ///
    /// # Arguments
    /// * `conversation_id` - the group/conversation id
    ///
    /// # Errors
    /// When the conversation is not found or there is no pending commit
    pub async fn clear_pending_commit(&mut self, conversation_id: &ConversationId) -> CryptoResult<()> {
        Self::get_conversation_mut(&mut self.mls_groups, conversation_id)?
            .clear_pending_commit(&self.mls_backend)
            .await
    }
}

#[cfg(test)]
pub mod tests {
    use openmls::prelude::Proposal;
    use wasm_bindgen_test::*;

    use crate::{
        credential::CredentialSupplier, prelude::MlsProposal, prelude::MlsProposalBundle, test_utils::*,
        MlsConversationConfiguration,
    };
    use openmls::prelude::AddProposal;
    use openmls::prelude::Proposal;

    use super::*;
    use crate::{
        credential::CredentialSupplier, prelude::MlsProposal, prelude::MlsProposalBundle, test_utils::*,
        MlsConversationConfiguration,
    };

    use super::*;

    wasm_bindgen_test_configure!(run_in_browser);

    pub mod commit_accepted {
        use super::*;

        #[apply(all_credential_types)]
        #[wasm_bindgen_test]
        pub async fn should_clear_pending_commit_and_proposals(credential: CredentialSupplier) {
            run_test_with_client_ids(credential, ["alice", "bob"], move |[mut alice_central, bob_central]| {
                Box::pin(async move {
                    let id = conversation_id();
                    alice_central
                        .new_conversation(id.clone(), MlsConversationConfiguration::default())
                        .await
                        .unwrap();
                    alice_central.new_proposal(&id, MlsProposal::Update).await.unwrap();
                    alice_central
                        .add_members_to_conversation(&id, &mut [bob_central.rnd_member().await])
                        .await
                        .unwrap();
                    assert!(!alice_central.pending_proposals(&id).is_empty());
                    assert!(alice_central.pending_commit(&id).is_some());
                    alice_central.commit_accepted(&id).await.unwrap();
                    assert!(alice_central.pending_commit(&id).is_none());
                    assert!(alice_central.pending_proposals(&id).is_empty());
                })
            })
            .await
        }
    }

    pub mod clear_pending_proposal {
        use super::*;

        #[apply(all_credential_types)]
        #[wasm_bindgen_test]
        pub async fn should_remove_proposal(credential: CredentialSupplier) {
            run_test_with_client_ids(
                credential,
                ["alice", "bob", "charlie"],
                move |[mut alice_central, mut bob_central, charlie_central]| {
                    Box::pin(async move {
                        let id = conversation_id();
                        alice_central
                            .new_conversation(id.clone(), MlsConversationConfiguration::default())
                            .await
                            .unwrap();
                        alice_central.invite(&id, &mut bob_central).await.unwrap();
                        assert!(alice_central.pending_proposals(&id).is_empty());

                        let charlie_kp = charlie_central.get_one_key_package().await;
                        let MlsProposalBundle {
                            proposal_ref: add_ref, ..
                        } = alice_central
                            .new_proposal(&id, MlsProposal::Add(charlie_kp))
                            .await
                            .unwrap();

                        let MlsProposalBundle {
                            proposal_ref: remove_ref,
                            ..
                        } = alice_central
                            .new_proposal(&id, MlsProposal::Remove(b"bob"[..].into()))
                            .await
                            .unwrap();

                        let MlsProposalBundle {
                            proposal_ref: update_ref,
                            ..
                        } = alice_central.new_proposal(&id, MlsProposal::Update).await.unwrap();

                        assert_eq!(alice_central.pending_proposals(&id).len(), 3);
                        alice_central.clear_pending_proposal(&id, add_ref.into()).await.unwrap();
                        assert_eq!(alice_central.pending_proposals(&id).len(), 2);
                        assert!(!alice_central
                            .pending_proposals(&id)
                            .into_iter()
                            .any(|p| matches!(p.proposal(), Proposal::Add(_))));

                        alice_central
                            .clear_pending_proposal(&id, remove_ref.into())
                            .await
                            .unwrap();
                        assert_eq!(alice_central.pending_proposals(&id).len(), 1);
                        assert!(!alice_central
                            .pending_proposals(&id)
                            .into_iter()
                            .any(|p| matches!(p.proposal(), Proposal::Remove(_))));

                        alice_central
                            .clear_pending_proposal(&id, update_ref.into())
                            .await
                            .unwrap();
                        assert!(alice_central.pending_proposals(&id).is_empty());
                        assert!(!alice_central
                            .pending_proposals(&id)
                            .into_iter()
                            .any(|p| matches!(p.proposal(), Proposal::Update(_))));
                    })
                },
            )
            .await
        }

        #[apply(all_credential_types)]
        #[wasm_bindgen_test]
        pub async fn should_fail_when_conversation_not_found(credential: CredentialSupplier) {
            run_test_with_client_ids(credential, ["alice"], move |[mut alice_central]| {
                Box::pin(async move {
                    let id = conversation_id();
                    let simple_ref = MlsProposalRef::try_from(vec![0; 16]).unwrap().into();
                    let clear = alice_central.clear_pending_proposal(&id, simple_ref).await;
                    assert!(matches!(clear.unwrap_err(), CryptoError::ConversationNotFound(conv_id) if conv_id == id))
                })
            })
            .await
        }

        #[apply(all_credential_types)]
        #[wasm_bindgen_test]
        pub async fn should_fail_when_proposal_ref_not_found(credential: CredentialSupplier) {
            run_test_with_client_ids(credential, ["alice"], move |[mut alice_central]| {
                Box::pin(async move {
                    let id = conversation_id();
                    alice_central
                        .new_conversation(id.clone(), MlsConversationConfiguration::default())
                        .await
                        .unwrap();
                    assert!(alice_central.pending_proposals(&id).is_empty());
                    let any_ref = MlsProposalRef::try_from(vec![0; 16]).unwrap();
                    let clear = alice_central.clear_pending_proposal(&id, any_ref.into()).await;
                    assert!(matches!(clear.unwrap_err(), CryptoError::PendingProposalNotFound(prop_ref) if prop_ref == any_ref))
                })
            })
            .await
        }
    }

    pub mod clear_pending_commit {
        use super::*;

        #[apply(all_credential_types)]
        #[wasm_bindgen_test]
        pub async fn should_remove_commit(credential: CredentialSupplier) {
            run_test_with_client_ids(credential, ["alice"], move |[mut alice_central]| {
                Box::pin(async move {
                    let id = conversation_id();
                    alice_central
                        .new_conversation(id.clone(), MlsConversationConfiguration::default())
                        .await
                        .unwrap();
                    assert!(alice_central.pending_commit(&id).is_none());

                    alice_central.update_keying_material(&id).await.unwrap();
                    assert!(alice_central.pending_commit(&id).is_some());
                    alice_central.clear_pending_commit(&id).await.unwrap();
                    assert!(alice_central.pending_commit(&id).is_none());
                })
            })
            .await
        }

        #[apply(all_credential_types)]
        #[wasm_bindgen_test]
        pub async fn should_fail_when_conversation_not_found(credential: CredentialSupplier) {
            run_test_with_client_ids(credential, ["alice"], move |[mut alice_central]| {
                Box::pin(async move {
                    let id = conversation_id();
                    let clear = alice_central.clear_pending_commit(&id).await;
                    assert!(matches!(clear.unwrap_err(), CryptoError::ConversationNotFound(conv_id) if conv_id == id))
                })
            })
            .await
        }

        #[apply(all_credential_types)]
        #[wasm_bindgen_test]
        pub async fn should_fail_when_pending_commit_absent(credential: CredentialSupplier) {
            run_test_with_client_ids(credential, ["alice"], move |[mut alice_central]| {
                Box::pin(async move {
                    let id = conversation_id();
                    alice_central
                        .new_conversation(id.clone(), MlsConversationConfiguration::default())
                        .await
                        .unwrap();
                    assert!(alice_central.pending_commit(&id).is_none());
                    let clear = alice_central.clear_pending_commit(&id).await;
                    assert!(matches!(clear.unwrap_err(), CryptoError::PendingCommitNotFound))
                })
            })
            .await
        }
    }
}
