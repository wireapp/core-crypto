use openmls::prelude::{KeyPackageRef, Proposal, QueuedProposal, Sender, StagedCommit};

use mls_crypto_provider::MlsCryptoProvider;

use crate::prelude::handshake::MlsProposalBundle;
use crate::{CryptoError, CryptoResult, MlsConversation};

/// Marker struct holding methods responsible for restoring (renewing) proposals (or pending commit)
/// in case another commit has been accepted by the backend instead of ours
pub(crate) struct Renew;

impl Renew {
    /// Renews proposals:
    /// * in pending_proposals but not in valid commit
    /// * in pending_commit but not in valid commit
    ///
    /// NB: we do not deal with partial commit (commit which do not contain all pending proposals)
    /// because they cannot be created at the moment by core-crypto
    ///
    /// * `self_kpr` - own client [KeyPackageRef] in current MLS group
    /// * `pending_proposals` - local pending proposals in group's proposal store
    /// * `pending_commit` - local pending commit which is now invalid
    /// * `valid_commit` - commit accepted by the backend which will now supersede our local pending commit
    pub(crate) fn renew<'a>(
        self_kpr: Option<KeyPackageRef>,
        pending_proposals: impl Iterator<Item = QueuedProposal> + 'a,
        pending_commit: Option<&'a StagedCommit>,
        valid_commit: &'a StagedCommit,
    ) -> (Vec<QueuedProposal>, bool) {
        // indicates if we need to renew an update proposal.
        // true only if we have an empty pending commit or the valid commit does not contain one of our update proposal
        // otherwise, local orphan update proposal will be renewed regularly, without this flag
        let mut update_self = false;

        let renewed_pending_proposals = if let Some(pending_commit) = pending_commit {
            // present in pending commit but not in valid commit
            let commit_proposals = pending_commit.staged_proposal_queue().cloned().collect::<Vec<_>>();

            // if our own pending commit is empty it means we were attempting to update
            let empty_commit = commit_proposals.is_empty();

            // does the valid commit contains one of our update proposal ?
            let valid_commit_has_self_update_proposal = valid_commit.update_proposals().any(|p| match p.sender() {
                Sender::Member(sender_kpr) => self_kpr.as_ref() == Some(sender_kpr),
                _ => false,
            });
            update_self = empty_commit && !valid_commit_has_self_update_proposal;

            // local proposals present in local pending commit but not in valid commit
            commit_proposals
                .into_iter()
                .filter_map(|p| Self::is_proposal_renewable(p, Some(valid_commit)))
                .collect::<Vec<_>>()
        } else {
            // local pending proposals present locally but not in valid commit
            pending_proposals
                .filter_map(|p| Self::is_proposal_renewable(p, Some(valid_commit)))
                .collect::<Vec<_>>()
        };
        (renewed_pending_proposals, update_self)
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
                Proposal::Update(ref update) => commit
                    .update_proposals()
                    .any(|p| p.update_proposal().key_package() == update.key_package()),
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
        update_self: bool,
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
        if update_self {
            result.push(self.propose_self_update(backend).await?);
        }
        Ok(result)
    }

    pub(crate) fn self_pending_proposals(&self) -> impl Iterator<Item = &QueuedProposal> {
        self.group.pending_proposals().filter(|&p| match p.sender() {
            Sender::Member(sender_kpr) => self.group.key_package_ref() == Some(sender_kpr),
            _ => false,
        })
    }
}

#[cfg(test)]
pub mod tests {
    use wasm_bindgen_test::*;

    use crate::{credential::CredentialSupplier, prelude::MlsProposal, test_utils::*, MlsConversationConfiguration};

    mod update {
        use super::*;

        #[apply(all_credential_types)]
        #[wasm_bindgen_test]
        pub async fn renewable_when_created_by_self(credential: CredentialSupplier) {
            run_test_with_client_ids(
                credential,
                ["alice", "bob"],
                move |[mut alice_central, mut bob_central]| {
                    Box::pin(async move {
                        let id = conversation_id();
                        alice_central
                            .new_conversation(id.clone(), MlsConversationConfiguration::default())
                            .await
                            .unwrap();
                        alice_central.invite(&id, &mut bob_central).await.unwrap();

                        assert!(alice_central.pending_proposals(&id).is_empty());
                        alice_central.new_proposal(&id, MlsProposal::Update).await.unwrap();
                        assert_eq!(alice_central.pending_proposals(&id).len(), 1);

                        // Bob hasn't Alice's proposal but creates a commit
                        let commit = bob_central.update_keying_material(&id).await.unwrap().commit;
                        bob_central.commit_accepted(&id).await.unwrap();

                        let proposals = alice_central
                            .decrypt_message(&id, commit.to_bytes().unwrap())
                            .await
                            .unwrap()
                            .proposals;
                        // Alice should renew the proposal because its her's
                        assert_eq!(alice_central.pending_proposals(&id).len(), 1);
                        assert_eq!(proposals.len(), alice_central.pending_proposals(&id).len());

                        // It should also renew the proposal when in pending_commit
                        alice_central.commit_pending_proposals(&id).await.unwrap();
                        assert!(alice_central.pending_commit(&id).is_some());
                        let commit = bob_central.update_keying_material(&id).await.unwrap().commit;
                        let proposals = alice_central
                            .decrypt_message(&id, commit.to_bytes().unwrap())
                            .await
                            .unwrap()
                            .proposals;
                        // Alice should renew the proposal because its her's
                        // It should also replace existing one
                        assert_eq!(alice_central.pending_proposals(&id).len(), 1);
                        assert_eq!(proposals.len(), alice_central.pending_proposals(&id).len());
                    })
                },
            )
            .await
        }

        #[apply(all_credential_types)]
        #[wasm_bindgen_test]
        pub async fn renews_pending_commit_when_created_by_self(credential: CredentialSupplier) {
            run_test_with_client_ids(
                credential,
                ["alice", "bob"],
                move |[mut alice_central, mut bob_central]| {
                    Box::pin(async move {
                        let id = conversation_id();
                        alice_central
                            .new_conversation(id.clone(), MlsConversationConfiguration::default())
                            .await
                            .unwrap();
                        alice_central.invite(&id, &mut bob_central).await.unwrap();

                        alice_central.update_keying_material(&id).await.unwrap();
                        assert!(alice_central.pending_commit(&id).is_some());

                        // but Bob creates a commit meanwhile
                        let commit = bob_central.update_keying_material(&id).await.unwrap().commit;

                        let proposals = alice_central
                            .decrypt_message(&id, commit.to_bytes().unwrap())
                            .await
                            .unwrap()
                            .proposals;
                        // Alice should renew the proposal because its her's
                        assert_eq!(alice_central.pending_proposals(&id).len(), 1);
                        assert_eq!(proposals.len(), alice_central.pending_proposals(&id).len());
                    })
                },
            )
            .await
        }

        #[apply(all_credential_types)]
        #[wasm_bindgen_test]
        pub async fn not_renewable_when_in_valid_commit(credential: CredentialSupplier) {
            run_test_with_client_ids(
                credential,
                ["alice", "bob"],
                move |[mut alice_central, mut bob_central]| {
                    Box::pin(async move {
                        let id = conversation_id();
                        alice_central
                            .new_conversation(id.clone(), MlsConversationConfiguration::default())
                            .await
                            .unwrap();
                        alice_central.invite(&id, &mut bob_central).await.unwrap();

                        assert!(alice_central.pending_proposals(&id).is_empty());
                        let proposal = alice_central
                            .new_proposal(&id, MlsProposal::Update)
                            .await
                            .unwrap()
                            .proposal;
                        assert_eq!(alice_central.pending_proposals(&id).len(), 1);

                        // Bob has Alice's update proposal
                        bob_central
                            .decrypt_message(&id, proposal.to_bytes().unwrap())
                            .await
                            .unwrap();

                        let commit = bob_central.update_keying_material(&id).await.unwrap().commit;
                        bob_central.commit_accepted(&id).await.unwrap();

                        // Bob's commit has Alice's proposal
                        let proposals = alice_central
                            .decrypt_message(&id, commit.to_bytes().unwrap())
                            .await
                            .unwrap()
                            .proposals;
                        // Alice proposal should not be renew as it was in valid commit
                        assert!(alice_central.pending_proposals(&id).is_empty());
                        assert_eq!(proposals.len(), alice_central.pending_proposals(&id).len());

                        // Same if proposal is also in pending commit
                        let proposal = alice_central
                            .new_proposal(&id, MlsProposal::Update)
                            .await
                            .unwrap()
                            .proposal;
                        alice_central.commit_pending_proposals(&id).await.unwrap();
                        assert_eq!(alice_central.pending_proposals(&id).len(), 1);
                        assert!(alice_central.pending_commit(&id).is_some());
                        bob_central
                            .decrypt_message(&id, proposal.to_bytes().unwrap())
                            .await
                            .unwrap();
                        let commit = bob_central.update_keying_material(&id).await.unwrap().commit;
                        let proposals = alice_central
                            .decrypt_message(&id, commit.to_bytes().unwrap())
                            .await
                            .unwrap()
                            .proposals;
                        // Alice should not be renew as it was in valid commit
                        assert!(alice_central.pending_proposals(&id).is_empty());
                        assert_eq!(proposals.len(), alice_central.pending_proposals(&id).len());
                    })
                },
            )
            .await
        }

        #[apply(all_credential_types)]
        #[wasm_bindgen_test]
        pub async fn not_renewable_by_ref(credential: CredentialSupplier) {
            run_test_with_client_ids(
                credential,
                ["alice", "bob", "charlie"],
                move |[mut alice_central, mut bob_central, mut charlie_central]| {
                    Box::pin(async move {
                        let id = conversation_id();
                        alice_central
                            .new_conversation(id.clone(), MlsConversationConfiguration::default())
                            .await
                            .unwrap();
                        alice_central.invite(&id, &mut bob_central).await.unwrap();
                        let pgs = alice_central.verifiable_public_group_state(&id).await;
                        charlie_central
                            .try_join_from_public_group_state(&id, pgs, vec![&mut alice_central, &mut bob_central])
                            .await
                            .unwrap();

                        let proposal = bob_central
                            .new_proposal(&id, MlsProposal::Update)
                            .await
                            .unwrap()
                            .proposal;
                        assert!(alice_central.pending_proposals(&id).is_empty());
                        alice_central
                            .decrypt_message(&id, proposal.to_bytes().unwrap())
                            .await
                            .unwrap();
                        assert_eq!(alice_central.pending_proposals(&id).len(), 1);

                        // Charlie does not have other proposals, it creates a commit
                        let commit = charlie_central.update_keying_material(&id).await.unwrap().commit;
                        let proposals = alice_central
                            .decrypt_message(&id, commit.to_bytes().unwrap())
                            .await
                            .unwrap()
                            .proposals;
                        // Alice should not renew Bob's update proposal
                        assert!(alice_central.pending_proposals(&id).is_empty());
                        assert_eq!(proposals.len(), alice_central.pending_proposals(&id).len());
                    })
                },
            )
            .await
        }
    }

    mod add {
        use super::*;

        #[apply(all_credential_types)]
        #[wasm_bindgen_test]
        pub async fn not_renewable_when_valid_commit_adds_same(credential: CredentialSupplier) {
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

                        let charlie_kp = charlie_central.get_one_key_package().await;
                        assert!(alice_central.pending_proposals(&id).is_empty());
                        alice_central
                            .new_proposal(&id, MlsProposal::Add(charlie_kp))
                            .await
                            .unwrap();
                        assert_eq!(alice_central.pending_proposals(&id).len(), 1);

                        let commit = bob_central
                            .add_members_to_conversation(&id, &mut [charlie_central.rnd_member().await])
                            .await
                            .unwrap()
                            .commit;
                        let proposals = alice_central
                            .decrypt_message(&id, commit.to_bytes().unwrap())
                            .await
                            .unwrap()
                            .proposals;
                        // Alice proposal is not renewed since she also wanted to add Charlie
                        assert!(alice_central.pending_proposals(&id).is_empty());
                        assert_eq!(proposals.len(), alice_central.pending_proposals(&id).len());
                    })
                },
            )
            .await
        }

        #[apply(all_credential_types)]
        #[wasm_bindgen_test]
        pub async fn not_renewable_in_pending_commit_when_valid_commit_adds_same(credential: CredentialSupplier) {
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

                        let charlie_kp = charlie_central.get_one_key_package().await;
                        assert!(alice_central.pending_proposals(&id).is_empty());
                        alice_central
                            .new_proposal(&id, MlsProposal::Add(charlie_kp))
                            .await
                            .unwrap();
                        assert_eq!(alice_central.pending_proposals(&id).len(), 1);

                        // Here Alice also creates a commit
                        alice_central.commit_pending_proposals(&id).await.unwrap();
                        assert!(alice_central.pending_commit(&id).is_some());

                        let commit = bob_central
                            .add_members_to_conversation(&id, &mut [charlie_central.rnd_member().await])
                            .await
                            .unwrap()
                            .commit;
                        let proposals = alice_central
                            .decrypt_message(&id, commit.to_bytes().unwrap())
                            .await
                            .unwrap()
                            .proposals;
                        // Alice proposal is not renewed since she also wanted to add Charlie
                        assert!(alice_central.pending_proposals(&id).is_empty());
                        assert_eq!(proposals.len(), alice_central.pending_proposals(&id).len());
                    })
                },
            )
            .await
        }

        #[apply(all_credential_types)]
        #[wasm_bindgen_test]
        pub async fn not_renewable_by_ref(credential: CredentialSupplier) {
            run_test_with_client_ids(
                credential,
                ["alice", "bob", "charlie", "debbie"],
                move |[mut alice_central, mut bob_central, mut charlie_central, debbie_central]| {
                    Box::pin(async move {
                        let id = conversation_id();
                        alice_central
                            .new_conversation(id.clone(), MlsConversationConfiguration::default())
                            .await
                            .unwrap();
                        alice_central.invite(&id, &mut bob_central).await.unwrap();
                        let pgs = alice_central.verifiable_public_group_state(&id).await;
                        charlie_central
                            .try_join_from_public_group_state(&id, pgs, vec![&mut alice_central, &mut bob_central])
                            .await
                            .unwrap();

                        // Bob will propose adding Debbie
                        let debbie_kp = debbie_central.get_one_key_package().await;
                        let proposal = bob_central
                            .new_proposal(&id, MlsProposal::Add(debbie_kp))
                            .await
                            .unwrap()
                            .proposal;
                        alice_central
                            .decrypt_message(&id, proposal.to_bytes().unwrap())
                            .await
                            .unwrap();
                        assert_eq!(alice_central.pending_proposals(&id).len(), 1);

                        // But Charlie will commit meanwhile
                        let commit = charlie_central.update_keying_material(&id).await.unwrap().commit;
                        let proposals = alice_central
                            .decrypt_message(&id, commit.to_bytes().unwrap())
                            .await
                            .unwrap()
                            .proposals;
                        // which Alice should not renew since it's not hers
                        assert!(alice_central.pending_proposals(&id).is_empty());
                        assert_eq!(proposals.len(), alice_central.pending_proposals(&id).len());
                    })
                },
            )
            .await
        }

        #[apply(all_credential_types)]
        #[wasm_bindgen_test]
        pub async fn renewable_when_valid_commit_doesnt_adds_same(credential: CredentialSupplier) {
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

                        // Alice proposes adding Charlie
                        let charlie_kp = charlie_central.get_one_key_package().await;
                        assert!(alice_central.pending_proposals(&id).is_empty());
                        alice_central
                            .new_proposal(&id, MlsProposal::Add(charlie_kp))
                            .await
                            .unwrap();
                        assert_eq!(alice_central.pending_proposals(&id).len(), 1);

                        // But meanwhile Bob will create a commit without Alice's proposal
                        let commit = bob_central.update_keying_material(&id).await.unwrap().commit;
                        bob_central.commit_accepted(&id).await.unwrap();
                        let proposals = alice_central
                            .decrypt_message(&id, commit.to_bytes().unwrap())
                            .await
                            .unwrap()
                            .proposals;
                        // So Alice proposal should be renewed
                        assert_eq!(alice_central.pending_proposals(&id).len(), 1);
                        assert_eq!(proposals.len(), alice_central.pending_proposals(&id).len());

                        // And same should happen when proposal is in pending commit
                        alice_central.commit_pending_proposals(&id).await.unwrap();
                        assert!(alice_central.pending_commit(&id).is_some());
                        let commit = bob_central.update_keying_material(&id).await.unwrap().commit;
                        let proposals = alice_central
                            .decrypt_message(&id, commit.to_bytes().unwrap())
                            .await
                            .unwrap()
                            .proposals;
                        // So Alice proposal should also be renewed
                        // It should also replace existing one
                        assert_eq!(alice_central.pending_proposals(&id).len(), 1);
                        assert_eq!(proposals.len(), alice_central.pending_proposals(&id).len());
                    })
                },
            )
            .await
        }

        #[apply(all_credential_types)]
        #[wasm_bindgen_test]
        pub async fn renews_pending_commit_when_valid_commit_doesnt_adds_same(credential: CredentialSupplier) {
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

                        // Alice commits adding Charlie
                        alice_central
                            .add_members_to_conversation(&id, &mut [charlie_central.rnd_member().await])
                            .await
                            .unwrap();
                        assert!(alice_central.pending_commit(&id).is_some());

                        // But meanwhile Bob will create a commit
                        let commit = bob_central.update_keying_material(&id).await.unwrap().commit;
                        let proposals = alice_central
                            .decrypt_message(&id, commit.to_bytes().unwrap())
                            .await
                            .unwrap()
                            .proposals;
                        // So Alice proposal should be renewed
                        assert_eq!(alice_central.pending_proposals(&id).len(), 1);
                        assert_eq!(proposals.len(), alice_central.pending_proposals(&id).len());
                    })
                },
            )
            .await
        }
    }

    mod remove {
        use super::*;

        #[apply(all_credential_types)]
        #[wasm_bindgen_test]
        pub async fn not_renewable_when_valid_commit_removes_same(credential: CredentialSupplier) {
            run_test_with_client_ids(
                credential,
                ["alice", "bob", "charlie"],
                move |[mut alice_central, mut bob_central, mut charlie_central]| {
                    Box::pin(async move {
                        let id = conversation_id();
                        alice_central
                            .new_conversation(id.clone(), MlsConversationConfiguration::default())
                            .await
                            .unwrap();
                        alice_central.invite(&id, &mut bob_central).await.unwrap();
                        let pgs = alice_central.verifiable_public_group_state(&id).await;
                        charlie_central
                            .try_join_from_public_group_state(&id, pgs, vec![&mut alice_central, &mut bob_central])
                            .await
                            .unwrap();

                        assert!(alice_central.pending_proposals(&id).is_empty());
                        alice_central
                            .new_proposal(&id, MlsProposal::Remove(b"charlie"[..].into()))
                            .await
                            .unwrap();
                        assert_eq!(alice_central.pending_proposals(&id).len(), 1);

                        let commit = bob_central
                            .remove_members_from_conversation(&id, &["charlie".into()])
                            .await
                            .unwrap()
                            .commit;
                        let proposals = alice_central
                            .decrypt_message(&id, commit.to_bytes().unwrap())
                            .await
                            .unwrap()
                            .proposals;
                        // Remove proposal is not renewed since commit does same
                        assert!(alice_central.pending_proposals(&id).is_empty());
                        assert_eq!(proposals.len(), alice_central.pending_proposals(&id).len());
                    })
                },
            )
            .await
        }

        #[apply(all_credential_types)]
        #[wasm_bindgen_test]
        pub async fn not_renewable_by_ref(credential: CredentialSupplier) {
            run_test_with_client_ids(
                credential,
                ["alice", "bob", "charlie"],
                move |[mut alice_central, mut bob_central, mut charlie_central]| {
                    Box::pin(async move {
                        let id = conversation_id();
                        alice_central
                            .new_conversation(id.clone(), MlsConversationConfiguration::default())
                            .await
                            .unwrap();
                        alice_central.invite(&id, &mut bob_central).await.unwrap();
                        let pgs = alice_central.verifiable_public_group_state(&id).await;
                        charlie_central
                            .try_join_from_public_group_state(&id, pgs, vec![&mut alice_central, &mut bob_central])
                            .await
                            .unwrap();

                        let proposal = bob_central
                            .new_proposal(&id, MlsProposal::Remove(b"charlie"[..].into()))
                            .await
                            .unwrap()
                            .proposal;
                        assert!(alice_central.pending_proposals(&id).is_empty());
                        alice_central
                            .decrypt_message(&id, proposal.to_bytes().unwrap())
                            .await
                            .unwrap();
                        assert_eq!(alice_central.pending_proposals(&id).len(), 1);

                        let commit = charlie_central.update_keying_material(&id).await.unwrap().commit;
                        let proposals = alice_central
                            .decrypt_message(&id, commit.to_bytes().unwrap())
                            .await
                            .unwrap()
                            .proposals;
                        // Remove proposal is not renewed since by ref
                        assert!(alice_central.pending_proposals(&id).is_empty());
                        assert_eq!(proposals.len(), alice_central.pending_proposals(&id).len());
                    })
                },
            )
            .await
        }

        #[apply(all_credential_types)]
        #[wasm_bindgen_test]
        pub async fn renewable_when_valid_commit_doesnt_remove_same(credential: CredentialSupplier) {
            run_test_with_client_ids(
                credential,
                ["alice", "bob", "charlie", "debbie"],
                move |[mut alice_central, mut bob_central, mut charlie_central, mut debbie_central]| {
                    Box::pin(async move {
                        let id = conversation_id();
                        alice_central
                            .new_conversation(id.clone(), MlsConversationConfiguration::default())
                            .await
                            .unwrap();
                        alice_central.invite(&id, &mut bob_central).await.unwrap();
                        let pgs = alice_central.verifiable_public_group_state(&id).await;
                        charlie_central
                            .try_join_from_public_group_state(&id, pgs, vec![&mut alice_central, &mut bob_central])
                            .await
                            .unwrap();
                        let pgs = alice_central.verifiable_public_group_state(&id).await;
                        debbie_central
                            .try_join_from_public_group_state(
                                &id,
                                pgs,
                                vec![&mut alice_central, &mut bob_central, &mut charlie_central],
                            )
                            .await
                            .unwrap();

                        // Alice wants to remove Charlie
                        assert!(alice_central.pending_proposals(&id).is_empty());
                        alice_central
                            .new_proposal(&id, MlsProposal::Remove(b"charlie"[..].into()))
                            .await
                            .unwrap();
                        assert_eq!(alice_central.pending_proposals(&id).len(), 1);

                        // Whereas Bob wants to remove Debbie
                        let commit = bob_central
                            .remove_members_from_conversation(&id, &["debbie".into()])
                            .await
                            .unwrap()
                            .commit;
                        let proposals = alice_central
                            .decrypt_message(&id, commit.to_bytes().unwrap())
                            .await
                            .unwrap()
                            .proposals;
                        // Remove is renewed since valid commit removes another
                        assert_eq!(alice_central.pending_proposals(&id).len(), 1);
                        assert_eq!(proposals.len(), alice_central.pending_proposals(&id).len());
                    })
                },
            )
            .await
        }

        #[apply(all_credential_types)]
        #[wasm_bindgen_test]
        pub async fn renews_pending_commit_when_commit_doesnt_remove_same(credential: CredentialSupplier) {
            run_test_with_client_ids(
                credential,
                ["alice", "bob", "charlie", "debbie"],
                move |[mut alice_central, mut bob_central, mut charlie_central, mut debbie_central]| {
                    Box::pin(async move {
                        let id = conversation_id();
                        alice_central
                            .new_conversation(id.clone(), MlsConversationConfiguration::default())
                            .await
                            .unwrap();
                        alice_central.invite(&id, &mut bob_central).await.unwrap();
                        let pgs = alice_central.verifiable_public_group_state(&id).await;
                        charlie_central
                            .try_join_from_public_group_state(&id, pgs, vec![&mut alice_central, &mut bob_central])
                            .await
                            .unwrap();
                        let pgs = alice_central.verifiable_public_group_state(&id).await;
                        debbie_central
                            .try_join_from_public_group_state(
                                &id,
                                pgs,
                                vec![&mut alice_central, &mut bob_central, &mut charlie_central],
                            )
                            .await
                            .unwrap();

                        // Alice wants to remove Charlie
                        alice_central
                            .remove_members_from_conversation(&id, &["charlie".into()])
                            .await
                            .unwrap();
                        assert!(alice_central.pending_commit(&id).is_some());

                        // Whereas Bob wants to remove Debbie
                        let commit = bob_central
                            .remove_members_from_conversation(&id, &["debbie".into()])
                            .await
                            .unwrap()
                            .commit;
                        let proposals = alice_central
                            .decrypt_message(&id, commit.to_bytes().unwrap())
                            .await
                            .unwrap()
                            .proposals;
                        // Remove is renewed since valid commit removes another
                        assert_eq!(alice_central.pending_proposals(&id).len(), 1);
                        assert_eq!(proposals.len(), alice_central.pending_proposals(&id).len());
                    })
                },
            )
            .await
        }

        #[apply(all_credential_types)]
        #[wasm_bindgen_test]
        pub async fn renews_pending_commit_from_proposal_when_commit_doesnt_remove_same(
            credential: CredentialSupplier,
        ) {
            run_test_with_client_ids(
                credential,
                ["alice", "bob", "charlie", "debbie"],
                move |[mut alice_central, mut bob_central, mut charlie_central, mut debbie_central]| {
                    Box::pin(async move {
                        let id = conversation_id();
                        alice_central
                            .new_conversation(id.clone(), MlsConversationConfiguration::default())
                            .await
                            .unwrap();
                        alice_central.invite(&id, &mut bob_central).await.unwrap();
                        let pgs = alice_central.verifiable_public_group_state(&id).await;
                        charlie_central
                            .try_join_from_public_group_state(&id, pgs, vec![&mut alice_central, &mut bob_central])
                            .await
                            .unwrap();
                        let pgs = alice_central.verifiable_public_group_state(&id).await;
                        debbie_central
                            .try_join_from_public_group_state(
                                &id,
                                pgs,
                                vec![&mut alice_central, &mut bob_central, &mut charlie_central],
                            )
                            .await
                            .unwrap();

                        // Alice wants to remove Charlie
                        alice_central
                            .new_proposal(&id, MlsProposal::Remove(b"charlie"[..].into()))
                            .await
                            .unwrap();
                        alice_central.commit_pending_proposals(&id).await.unwrap();
                        assert_eq!(alice_central.pending_proposals(&id).len(), 1);
                        assert!(alice_central.pending_commit(&id).is_some());

                        // Whereas Bob wants to remove Debbie
                        let commit = bob_central
                            .remove_members_from_conversation(&id, &["debbie".into()])
                            .await
                            .unwrap()
                            .commit;
                        let proposals = alice_central
                            .decrypt_message(&id, commit.to_bytes().unwrap())
                            .await
                            .unwrap()
                            .proposals;
                        // Remove is renewed since valid commit removes another
                        assert_eq!(alice_central.pending_proposals(&id).len(), 1);
                        assert_eq!(proposals.len(), alice_central.pending_proposals(&id).len());
                    })
                },
            )
            .await
        }
    }
}
