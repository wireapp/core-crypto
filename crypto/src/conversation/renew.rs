use openmls::prelude::{Proposal, QueuedProposal, Sender, StagedCommit};

use mls_crypto_provider::MlsCryptoProvider;

use crate::prelude::handshake::MlsProposalBundle;
use crate::{CryptoError, CryptoResult, MlsConversation};

/// Marker struct holding methods responsible for restoring (renewing) proposals (or pending commit)
/// in case another commit has been accepted by the backend instead of ours
pub(crate) struct Renew;

impl Renew {
    /// Renews proposals:
    /// * in pending_proposals but not in valid commit
    /// * in pending commit but not in valid commit
    ///
    /// * `pending_proposals` - local pending proposals in group's proposal store
    /// * `pending_commit` - local pending commit which is now invalid
    /// * `valid_commit` - commit accepted by the backend which will now supersede our local pending commit
    pub(crate) fn renew<'a>(
        pending_proposals: impl Iterator<Item = QueuedProposal> + 'a,
        pending_commit: Option<&'a StagedCommit>,
        valid_commit: &'a StagedCommit,
    ) -> Vec<QueuedProposal> {
        // present locally but not in valid commit
        let renewed_pending_proposals =
            pending_proposals.filter_map(|p| Self::is_proposal_renewable(p, Some(valid_commit)));

        if let Some(pending_commit) = pending_commit {
            // present in pending commit but not in valid commit
            let renewed_from_pending_commit = pending_commit
                .staged_proposal_queue()
                .cloned()
                .filter_map(|p| Self::is_proposal_renewable(p, Some(valid_commit)));
            renewed_pending_proposals.chain(renewed_from_pending_commit).collect()
        } else {
            renewed_pending_proposals.collect()
        }
    }

    /// A proposal has to be renewed if it is absent from supplied commit
    fn is_proposal_renewable(proposal: QueuedProposal, commit: Option<&StagedCommit>) -> Option<QueuedProposal> {
        if let Some(commit) = commit {
            let in_commit = match proposal.proposal() {
                Proposal::Add(ref add) => commit.add_proposals().any(|p| {
                    p.add_proposal().key_package().credential().identity() == add.key_package().credential().identity()
                }),
                Proposal::Remove(ref remove) => commit
                    .remove_proposals()
                    .any(|p| p.remove_proposal().removed() == remove.removed()),
                Proposal::Update(_) => false,
                _ => true,
            };
            if in_commit {
                None
            } else {
                Some(proposal)
            }
        } else {
            // if proposal is orphan (not present in commit)
            Some(proposal)
        }
    }
}

impl MlsConversation {
    /// Given the proposals to renew, actually restore them by using associated methods in [MlsGroup].
    /// This will also add them to the local proposal store
    pub(crate) async fn renew_proposals_for_current_epoch(
        &mut self,
        backend: &MlsCryptoProvider,
        proposals: impl Iterator<Item = QueuedProposal>,
    ) -> CryptoResult<Vec<MlsProposalBundle>> {
        let mut result = vec![];
        let is_external = |p: &QueuedProposal| matches!(p.sender(), Sender::External(_) | Sender::NewMember);
        let proposals = proposals.filter(|p| !is_external(p));
        for proposal in proposals {
            let msg = match proposal.proposal() {
                Proposal::Add(add) => self.propose_add_member(backend, add.key_package()).await?,
                Proposal::Remove(remove) => self.propose_remove_member(backend, remove.removed()).await?,
                Proposal::Update(_) => self.propose_self_update(backend).await?,
                _ => return Err(CryptoError::ImplementationError),
            };
            result.push(msg);
        }
        Ok(result)
    }
}

#[cfg(test)]
pub mod tests {
    use wasm_bindgen_test::*;

    use crate::{credential::CredentialSupplier, prelude::MlsProposal, test_utils::*, MlsConversationConfiguration};

    use super::*;

    mod is_renewable {
        use super::*;

        #[apply(all_credential_types)]
        #[wasm_bindgen_test]
        pub async fn is_renewable_when_commit_absent(credential: CredentialSupplier) {
            run_test_with_client_ids(credential, ["alice"], move |[mut alice_central]| {
                Box::pin(async move {
                    let id = conversation_id();
                    alice_central
                        .new_conversation(id.clone(), MlsConversationConfiguration::default())
                        .await
                        .unwrap();

                    alice_central.new_proposal(&id, MlsProposal::Update).await.unwrap();
                    let proposal = alice_central.pending_proposals(&id).first().unwrap().clone();

                    assert!(Renew::is_proposal_renewable(proposal, None).is_some())
                })
            })
            .await
        }

        #[apply(all_credential_types)]
        #[wasm_bindgen_test]
        pub async fn update_is_always_renewable(credential: CredentialSupplier) {
            run_test_with_client_ids(credential, ["alice"], move |[mut alice_central]| {
                Box::pin(async move {
                    let id = conversation_id();
                    alice_central
                        .new_conversation(id.clone(), MlsConversationConfiguration::default())
                        .await
                        .unwrap();
                    alice_central.new_proposal(&id, MlsProposal::Update).await.unwrap();
                    let proposal = alice_central.pending_proposals(&id).first().unwrap().clone();
                    alice_central[&id].group.clear_pending_proposals();

                    alice_central.update_keying_material(&id).await.unwrap();
                    let commit = alice_central.pending_commit(&id).unwrap().clone();
                    assert!(Renew::is_proposal_renewable(proposal, Some(&commit)).is_some())
                })
            })
            .await
        }

        #[apply(all_credential_types)]
        #[wasm_bindgen_test]
        pub async fn add_is_not_renewable_when_commit_already_adds_same(credential: CredentialSupplier) {
            run_test_with_client_ids(credential, ["alice", "bob"], move |[mut alice_central, bob_central]| {
                Box::pin(async move {
                    let id = conversation_id();
                    alice_central
                        .new_conversation(id.clone(), MlsConversationConfiguration::default())
                        .await
                        .unwrap();

                    let bob_kp = bob_central.get_one_key_package().await;
                    alice_central.new_proposal(&id, MlsProposal::Add(bob_kp)).await.unwrap();
                    let proposal = alice_central.pending_proposals(&id).first().unwrap().clone();
                    alice_central[&id].group.clear_pending_proposals();
                    assert!(alice_central.pending_proposals(&id).is_empty());

                    alice_central
                        .add_members_to_conversation(&id, &mut [bob_central.rnd_member().await])
                        .await
                        .unwrap();
                    let commit = alice_central.pending_commit(&id).unwrap().clone();
                    assert!(Renew::is_proposal_renewable(proposal, Some(&commit)).is_none())
                })
            })
            .await
        }

        #[apply(all_credential_types)]
        #[wasm_bindgen_test]
        pub async fn add_is_renewable_when_commit_doesnt_adds_same(credential: CredentialSupplier) {
            run_test_with_client_ids(
                credential,
                ["alice", "bob", "charlie"],
                move |[mut alice_central, bob_central, charlie_central]| {
                    Box::pin(async move {
                        let id = conversation_id();
                        alice_central
                            .new_conversation(id.clone(), MlsConversationConfiguration::default())
                            .await
                            .unwrap();

                        let bob_kp = bob_central.get_one_key_package().await;
                        alice_central.new_proposal(&id, MlsProposal::Add(bob_kp)).await.unwrap();
                        let proposal = alice_central.pending_proposals(&id).first().unwrap().clone();
                        alice_central[&id].group.clear_pending_proposals();

                        alice_central
                            .add_members_to_conversation(&id, &mut [charlie_central.rnd_member().await])
                            .await
                            .unwrap();
                        let commit = alice_central.pending_commit(&id).unwrap().clone();
                        assert!(Renew::is_proposal_renewable(proposal, Some(&commit)).is_some())
                    })
                },
            )
            .await
        }

        #[apply(all_credential_types)]
        #[wasm_bindgen_test]
        pub async fn remove_is_not_renewable_when_commit_already_removes_same(credential: CredentialSupplier) {
            run_test_with_client_ids(credential, ["alice", "bob"], move |[mut alice_central, bob_central]| {
                Box::pin(async move {
                    let id = conversation_id();
                    alice_central
                        .new_conversation(id.clone(), MlsConversationConfiguration::default())
                        .await
                        .unwrap();
                    alice_central
                        .add_members_to_conversation(&id, &mut [bob_central.rnd_member().await])
                        .await
                        .unwrap();
                    alice_central.commit_accepted(&id).await.unwrap();
                    assert_eq!(alice_central[&id].group.members().len(), 2);

                    alice_central
                        .new_proposal(&id, MlsProposal::Remove(b"bob"[..].into()))
                        .await
                        .unwrap();
                    let proposal = alice_central.pending_proposals(&id).first().unwrap().clone();
                    alice_central[&id].group.clear_pending_proposals();

                    alice_central
                        .remove_members_from_conversation(&id, &["bob".into()])
                        .await
                        .unwrap();
                    let commit = alice_central.pending_commit(&id).unwrap().clone();
                    assert!(Renew::is_proposal_renewable(proposal, Some(&commit)).is_none())
                })
            })
            .await
        }

        #[apply(all_credential_types)]
        #[wasm_bindgen_test]
        pub async fn remove_is_renewable_when_commit_doesnt_removes_same(credential: CredentialSupplier) {
            run_test_with_client_ids(
                credential,
                ["alice", "bob", "charlie"],
                move |[mut alice_central, bob_central, charlie_central]| {
                    Box::pin(async move {
                        let id = conversation_id();
                        alice_central
                            .new_conversation(id.clone(), MlsConversationConfiguration::default())
                            .await
                            .unwrap();
                        let members = &mut [bob_central.rnd_member().await, charlie_central.rnd_member().await];
                        alice_central.add_members_to_conversation(&id, members).await.unwrap();
                        alice_central.commit_accepted(&id).await.unwrap();
                        assert_eq!(alice_central[&id].group.members().len(), 3);

                        alice_central
                            .new_proposal(&id, MlsProposal::Remove(b"bob"[..].into()))
                            .await
                            .unwrap();
                        let proposal = alice_central.pending_proposals(&id).first().unwrap().clone();
                        alice_central[&id].group.clear_pending_proposals();

                        alice_central
                            .remove_members_from_conversation(&id, &["charlie".into()])
                            .await
                            .unwrap();
                        let commit = alice_central.pending_commit(&id).unwrap().clone();
                        assert!(Renew::is_proposal_renewable(proposal, Some(&commit)).is_some())
                    })
                },
            )
            .await
        }
    }
}
