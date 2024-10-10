use core_crypto_keystore::entities::MlsEncryptionKeyPair;
use openmls::prelude::{LeafNode, LeafNodeIndex, Proposal, QueuedProposal, Sender, StagedCommit};
use openmls_traits::OpenMlsCryptoProvider;

use mls_crypto_provider::TransactionalCryptoProvider;

use crate::prelude::{Client, CryptoError, CryptoResult, MlsConversation, MlsProposalBundle};

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
    /// * `self_index` - own client [KeyPackageRef] in current MLS group
    /// * `pending_proposals` - local pending proposals in group's proposal store
    /// * `pending_commit` - local pending commit which is now invalid
    /// * `valid_commit` - commit accepted by the backend which will now supersede our local pending commit
    #[cfg_attr(not(test), tracing::instrument(skip_all))]
    pub(crate) fn renew<'a>(
        self_index: &LeafNodeIndex,
        pending_proposals: impl Iterator<Item = QueuedProposal> + 'a,
        pending_commit: Option<&'a StagedCommit>,
        valid_commit: &'a StagedCommit,
    ) -> (Vec<QueuedProposal>, bool) {
        // indicates if we need to renew an update proposal.
        // true only if we have an empty pending commit or the valid commit does not contain one of our update proposal
        // otherwise, local orphan update proposal will be renewed regularly, without this flag
        let mut needs_update = false;

        let renewed_pending_proposals = if let Some(pending_commit) = pending_commit {
            // present in pending commit but not in valid commit
            let commit_proposals = pending_commit.queued_proposals().cloned().collect::<Vec<_>>();

            // if our own pending commit is empty it means we were attempting to update
            let empty_commit = commit_proposals.is_empty();

            // does the valid commit contains one of our update proposal ?
            let valid_commit_has_own_update_proposal = valid_commit.update_proposals().any(|p| match p.sender() {
                Sender::Member(sender_index) => self_index == sender_index,
                _ => false,
            });

            // do we need to renew the update or has it already been committed
            needs_update = !valid_commit_has_own_update_proposal && empty_commit;

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
        (renewed_pending_proposals, needs_update)
    }

    /// A proposal has to be renewed if it is absent from supplied commit
    fn is_proposal_renewable(proposal: QueuedProposal, commit: Option<&StagedCommit>) -> Option<QueuedProposal> {
        if let Some(commit) = commit {
            let in_commit = match proposal.proposal() {
                Proposal::Add(ref add) => commit.add_proposals().any(|p| {
                    let commits_identity = p.add_proposal().key_package().leaf_node().credential().identity();
                    let proposal_identity = add.key_package().leaf_node().credential().identity();
                    commits_identity == proposal_identity
                }),
                Proposal::Remove(ref remove) => commit
                    .remove_proposals()
                    .any(|p| p.remove_proposal().removed() == remove.removed()),
                Proposal::Update(ref update) => commit
                    .update_proposals()
                    .any(|p| p.update_proposal().leaf_node() == update.leaf_node()),
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
    #[cfg_attr(not(test), tracing::instrument(err, skip_all))]
    pub(crate) async fn renew_proposals_for_current_epoch(
        &mut self,
        client: &Client,
        backend: &TransactionalCryptoProvider,
        proposals: impl Iterator<Item = QueuedProposal>,
        needs_update: bool,
    ) -> CryptoResult<Vec<MlsProposalBundle>> {
        let mut bundle = vec![];
        let is_external = |p: &QueuedProposal| matches!(p.sender(), Sender::External(_) | Sender::NewMemberProposal);
        let proposals = proposals.filter(|p| !is_external(p));
        for proposal in proposals {
            let msg = match proposal.proposal {
                Proposal::Add(add) => self.propose_add_member(client, backend, add.key_package.into()).await?,
                Proposal::Remove(remove) => self.propose_remove_member(client, backend, remove.removed()).await?,
                Proposal::Update(update) => self.renew_update(client, backend, Some(update.leaf_node())).await?,
                _ => return Err(CryptoError::ImplementationError),
            };
            bundle.push(msg);
        }
        if needs_update {
            let proposal = self.renew_update(client, backend, None).await?;
            bundle.push(proposal);
        }
        Ok(bundle)
    }

    /// Renews an update proposal by considering the explicit LeafNode supplied in the proposal
    /// by applying it to the current own LeafNode.
    /// At this point, we have already verified we are only operating on proposals created by self.
    #[cfg_attr(not(test), tracing::instrument(err, skip_all))]
    async fn renew_update(
        &mut self,
        client: &Client,
        backend: &TransactionalCryptoProvider,
        leaf_node: Option<&LeafNode>,
    ) -> CryptoResult<MlsProposalBundle> {
        if let Some(leaf_node) = leaf_node {
            // Creating an update rekeys the LeafNode everytime. Hence we need to clear the previous
            // encryption key from the keystore otherwise we would have a leak
            backend
                .key_store()
                .remove::<MlsEncryptionKeyPair, _>(leaf_node.encryption_key().as_slice())
                .await?;
        }

        let mut leaf_node = leaf_node
            .or_else(|| self.group.own_leaf())
            .cloned()
            .ok_or(CryptoError::InternalMlsError)?;

        let sc = self.signature_scheme();
        let ct = self.own_credential_type()?;
        let cb = client
            .find_most_recent_credential_bundle(sc, ct)
            .ok_or(CryptoError::MlsNotInitialized)?;

        leaf_node.set_credential_with_key(cb.to_mls_credential_with_key());

        self.propose_explicit_self_update(client, backend, Some(leaf_node))
            .await
    }

    pub(crate) fn self_pending_proposals(&self) -> impl Iterator<Item = &QueuedProposal> {
        self.group
            .pending_proposals()
            .filter(|&p| matches!(p.sender(), Sender::Member(i) if i == &self.group.own_leaf_index()))
    }
}

#[cfg(test)]
mod tests {
    use wasm_bindgen_test::*;

    use crate::test_utils::*;

    mod update {
        use super::*;

        #[apply(all_cred_cipher)]
        #[wasm_bindgen_test]
        pub async fn renewable_when_created_by_self(case: TestCase) {
            run_test_with_client_ids(
                case.clone(),
                ["alice", "bob"],
                move |[mut alice_central, mut bob_central]| {
                    Box::pin(async move {
                        let id = conversation_id();
                        alice_central
                            .context
                            .new_conversation(&id, case.credential_type, case.cfg.clone())
                            .await
                            .unwrap();
                        alice_central
                            .invite_all(&case, &id, [&bob_central])
                            .await
                            .unwrap();

                        assert!(alice_central.pending_proposals(&id).await.is_empty());
                        alice_central.context.new_update_proposal(&id).await.unwrap();
                        assert_eq!(alice_central.pending_proposals(&id).await.len(), 1);

                        // Bob hasn't Alice's proposal but creates a commit
                        let commit = bob_central.context.update_keying_material(&id).await.unwrap().commit;
                        bob_central.context.commit_accepted(&id).await.unwrap();

                        let proposals = alice_central
                            .context
                            .decrypt_message(&id, commit.to_bytes().unwrap())
                            .await
                            .unwrap()
                            .proposals;
                        // Alice should renew the proposal because its hers
                        assert_eq!(alice_central.pending_proposals(&id).await.len(), 1);
                        assert_eq!(
                            proposals.len(),
                            alice_central.pending_proposals(&id).await.len()
                        );

                        // It should also renew the proposal when in pending_commit
                        alice_central.context.commit_pending_proposals(&id).await.unwrap();
                        assert!(alice_central.pending_commit(&id).await.is_some());
                        let commit = bob_central.context.update_keying_material(&id).await.unwrap().commit;
                        let proposals = alice_central
                            .context
                            .decrypt_message(&id, commit.to_bytes().unwrap())
                            .await
                            .unwrap()
                            .proposals;
                        // Alice should renew the proposal because its hers
                        // It should also replace existing one
                        assert_eq!(alice_central.pending_proposals(&id).await.len(), 1);
                        assert_eq!(
                            proposals.len(),
                            alice_central.pending_proposals(&id).await.len()
                        );
                    })
                },
            )
            .await
        }

        #[apply(all_cred_cipher)]
        #[wasm_bindgen_test]
        pub async fn renews_pending_commit_when_created_by_self(case: TestCase) {
            run_test_with_client_ids(
                case.clone(),
                ["alice", "bob"],
                move |[mut alice_central, mut bob_central]| {
                    Box::pin(async move {
                        let id = conversation_id();
                        alice_central
                            .context
                            .new_conversation(&id, case.credential_type, case.cfg.clone())
                            .await
                            .unwrap();
                        alice_central
                            .invite_all(&case, &id, [&bob_central])
                            .await
                            .unwrap();

                        alice_central.context.update_keying_material(&id).await.unwrap();
                        assert!(alice_central.pending_commit(&id).await.is_some());

                        // but Bob creates a commit meanwhile
                        let commit = bob_central.context.update_keying_material(&id).await.unwrap().commit;

                        let proposals = alice_central
                            .context
                            .decrypt_message(&id, commit.to_bytes().unwrap())
                            .await
                            .unwrap()
                            .proposals;
                        // Alice should renew the proposal because its her's
                        assert_eq!(alice_central.pending_proposals(&id).await.len(), 1);
                        assert_eq!(
                            proposals.len(),
                            alice_central.pending_proposals(&id).await.len()
                        );
                    })
                },
            )
            .await
        }

        #[apply(all_cred_cipher)]
        #[wasm_bindgen_test]
        pub async fn not_renewable_when_in_valid_commit(case: TestCase) {
            run_test_with_client_ids(
                case.clone(),
                ["alice", "bob"],
                move |[mut alice_central, mut bob_central]| {
                    Box::pin(async move {
                        let id = conversation_id();
                        alice_central
                            .context
                            .new_conversation(&id, case.credential_type, case.cfg.clone())
                            .await
                            .unwrap();
                        alice_central
                            .invite_all(&case, &id, [&bob_central])
                            .await
                            .unwrap();

                        assert!(alice_central.pending_proposals(&id).await.is_empty());
                        let proposal = alice_central.context.new_update_proposal(&id).await.unwrap().proposal;
                        assert_eq!(alice_central.pending_proposals(&id).await.len(), 1);

                        // Bob has Alice's update proposal
                        bob_central
                            .context
                            .decrypt_message(&id, proposal.to_bytes().unwrap())
                            .await
                            .unwrap();

                        let commit = bob_central.context.update_keying_material(&id).await.unwrap().commit;
                        bob_central.context.commit_accepted(&id).await.unwrap();

                        // Bob's commit has Alice's proposal
                        let proposals = alice_central
                            .context
                            .decrypt_message(&id, commit.to_bytes().unwrap())
                            .await
                            .unwrap()
                            .proposals;
                        // Alice proposal should not be renew as it was in valid commit
                        assert!(alice_central.pending_proposals(&id).await.is_empty());
                        assert_eq!(
                            proposals.len(),
                            alice_central.pending_proposals(&id).await.len()
                        );

                        // Same if proposal is also in pending commit
                        let proposal = alice_central.context.new_update_proposal(&id).await.unwrap().proposal;
                        alice_central.context.commit_pending_proposals(&id).await.unwrap();
                        assert_eq!(alice_central.pending_proposals(&id).await.len(), 1);
                        assert!(alice_central.pending_commit(&id).await.is_some());
                        bob_central
                            .context
                            .decrypt_message(&id, proposal.to_bytes().unwrap())
                            .await
                            .unwrap();
                        let commit = bob_central.context.update_keying_material(&id).await.unwrap().commit;
                        let proposals = alice_central
                            .context
                            .decrypt_message(&id, commit.to_bytes().unwrap())
                            .await
                            .unwrap()
                            .proposals;
                        // Alice should not be renew as it was in valid commit
                        assert!(alice_central.pending_proposals(&id).await.is_empty());
                        assert_eq!(
                            proposals.len(),
                            alice_central.pending_proposals(&id).await.len()
                        );
                    })
                },
            )
            .await
        }

        #[apply(all_cred_cipher)]
        #[wasm_bindgen_test]
        pub async fn not_renewable_by_ref(case: TestCase) {
            run_test_with_client_ids(
                case.clone(),
                ["alice", "bob", "charlie"],
                move |[mut alice_central, mut bob_central, mut charlie_central]| {
                    Box::pin(async move {
                        let id = conversation_id();
                        alice_central
                            .context
                            .new_conversation(&id, case.credential_type, case.cfg.clone())
                            .await
                            .unwrap();
                        alice_central
                            .invite_all(&case, &id, [&bob_central, &charlie_central])
                            .await
                            .unwrap();

                        let proposal = bob_central.context.new_update_proposal(&id).await.unwrap().proposal;
                        assert!(alice_central.pending_proposals(&id).await.is_empty());
                        alice_central
                            .context
                            .decrypt_message(&id, proposal.to_bytes().unwrap())
                            .await
                            .unwrap();
                        assert_eq!(alice_central.pending_proposals(&id).await.len(), 1);

                        // Charlie does not have other proposals, it creates a commit
                        let commit = charlie_central
                            .context
                            .update_keying_material(&id)
                            .await
                            .unwrap()
                            .commit;
                        let proposals = alice_central
                            .context
                            .decrypt_message(&id, commit.to_bytes().unwrap())
                            .await
                            .unwrap()
                            .proposals;
                        // Alice should not renew Bob's update proposal
                        assert!(alice_central.pending_proposals(&id).await.is_empty());
                        assert_eq!(
                            proposals.len(),
                            alice_central.pending_proposals(&id).await.len()
                        );
                    })
                },
            )
            .await
        }
    }

    mod add {
        use super::*;

        #[apply(all_cred_cipher)]
        #[wasm_bindgen_test]
        pub async fn not_renewable_when_valid_commit_adds_same(case: TestCase) {
            run_test_with_client_ids(
                case.clone(),
                ["alice", "bob", "charlie"],
                move |[mut alice_central, mut bob_central, charlie_central]| {
                    Box::pin(async move {
                        let id = conversation_id();
                        alice_central
                            .context
                            .new_conversation(&id, case.credential_type, case.cfg.clone())
                            .await
                            .unwrap();
                        alice_central
                            .invite_all(&case, &id, [&bob_central])
                            .await
                            .unwrap();

                        let charlie_kp = charlie_central.get_one_key_package(&case).await;
                        assert!(alice_central.pending_proposals(&id).await.is_empty());
                        alice_central.context.new_add_proposal(&id, charlie_kp).await.unwrap();
                        assert_eq!(alice_central.pending_proposals(&id).await.len(), 1);

                        let charlie = charlie_central.rand_key_package(&case).await;
                        let commit = bob_central
                            .context
                            .add_members_to_conversation(&id, vec![charlie])
                            .await
                            .unwrap()
                            .commit;
                        let proposals = alice_central
                            .context
                            .decrypt_message(&id, commit.to_bytes().unwrap())
                            .await
                            .unwrap()
                            .proposals;
                        // Alice proposal is not renewed since she also wanted to add Charlie
                        assert!(alice_central.pending_proposals(&id).await.is_empty());
                        assert_eq!(
                            proposals.len(),
                            alice_central.pending_proposals(&id).await.len()
                        );
                    })
                },
            )
            .await
        }

        #[apply(all_cred_cipher)]
        #[wasm_bindgen_test]
        pub async fn not_renewable_in_pending_commit_when_valid_commit_adds_same(case: TestCase) {
            run_test_with_client_ids(
                case.clone(),
                ["alice", "bob", "charlie"],
                move |[mut alice_central, mut bob_central, charlie_central]| {
                    Box::pin(async move {
                        let id = conversation_id();
                        alice_central
                            .context
                            .new_conversation(&id, case.credential_type, case.cfg.clone())
                            .await
                            .unwrap();
                        alice_central
                            .invite_all(&case, &id, [&bob_central])
                            .await
                            .unwrap();

                        let charlie_kp = charlie_central.get_one_key_package(&case).await;
                        assert!(alice_central.pending_proposals(&id).await.is_empty());
                        alice_central.context.new_add_proposal(&id, charlie_kp).await.unwrap();
                        assert_eq!(alice_central.pending_proposals(&id).await.len(), 1);

                        // Here Alice also creates a commit
                        alice_central.context.commit_pending_proposals(&id).await.unwrap();
                        assert!(alice_central.pending_commit(&id).await.is_some());

                        let charlie = charlie_central.rand_key_package(&case).await;
                        let commit = bob_central
                            .context
                            .add_members_to_conversation(&id, vec![charlie])
                            .await
                            .unwrap()
                            .commit;
                        let proposals = alice_central
                            .context
                            .decrypt_message(&id, commit.to_bytes().unwrap())
                            .await
                            .unwrap()
                            .proposals;
                        // Alice proposal is not renewed since she also wanted to add Charlie
                        assert!(alice_central.pending_proposals(&id).await.is_empty());
                        assert_eq!(
                            proposals.len(),
                            alice_central.pending_proposals(&id).await.len()
                        );
                    })
                },
            )
            .await
        }

        #[apply(all_cred_cipher)]
        #[wasm_bindgen_test]
        pub async fn not_renewable_by_ref(case: TestCase) {
            run_test_with_client_ids(
                case.clone(),
                ["alice", "bob", "charlie", "debbie"],
                move |[mut alice_central, mut bob_central, mut charlie_central, debbie_central]| {
                    Box::pin(async move {
                        let id = conversation_id();
                        alice_central
                            .context
                            .new_conversation(&id, case.credential_type, case.cfg.clone())
                            .await
                            .unwrap();
                        alice_central
                            .invite_all(&case, &id, [&bob_central, &charlie_central])
                            .await
                            .unwrap();

                        // Bob will propose adding Debbie
                        let debbie_kp = debbie_central.get_one_key_package(&case).await;
                        let proposal = bob_central
                            .context
                            .new_add_proposal(&id, debbie_kp)
                            .await
                            .unwrap()
                            .proposal;
                        alice_central
                            .context
                            .decrypt_message(&id, proposal.to_bytes().unwrap())
                            .await
                            .unwrap();
                        assert_eq!(alice_central.pending_proposals(&id).await.len(), 1);

                        // But Charlie will commit meanwhile
                        let commit = charlie_central
                            .context
                            .update_keying_material(&id)
                            .await
                            .unwrap()
                            .commit;
                        let proposals = alice_central
                            .context
                            .decrypt_message(&id, commit.to_bytes().unwrap())
                            .await
                            .unwrap()
                            .proposals;
                        // which Alice should not renew since it's not hers
                        assert!(alice_central.pending_proposals(&id).await.is_empty());
                        assert_eq!(
                            proposals.len(),
                            alice_central.pending_proposals(&id).await.len()
                        );
                    })
                },
            )
            .await
        }

        #[apply(all_cred_cipher)]
        #[wasm_bindgen_test]
        pub async fn renewable_when_valid_commit_doesnt_adds_same(case: TestCase) {
            run_test_with_client_ids(
                case.clone(),
                ["alice", "bob", "charlie"],
                move |[mut alice_central, mut bob_central, charlie_central]| {
                    Box::pin(async move {
                        let id = conversation_id();
                        alice_central
                            .context
                            .new_conversation(&id, case.credential_type, case.cfg.clone())
                            .await
                            .unwrap();
                        alice_central
                            .invite_all(&case, &id, [&bob_central])
                            .await
                            .unwrap();

                        // Alice proposes adding Charlie
                        let charlie_kp = charlie_central.get_one_key_package(&case).await;
                        assert!(alice_central.pending_proposals(&id).await.is_empty());
                        alice_central.context.new_add_proposal(&id, charlie_kp).await.unwrap();
                        assert_eq!(alice_central.pending_proposals(&id).await.len(), 1);

                        // But meanwhile Bob will create a commit without Alice's proposal
                        let commit = bob_central.context.update_keying_material(&id).await.unwrap().commit;
                        bob_central.context.commit_accepted(&id).await.unwrap();
                        let proposals = alice_central
                            .context
                            .decrypt_message(&id, commit.to_bytes().unwrap())
                            .await
                            .unwrap()
                            .proposals;
                        // So Alice proposal should be renewed
                        assert_eq!(alice_central.pending_proposals(&id).await.len(), 1);
                        assert_eq!(
                            proposals.len(),
                            alice_central.pending_proposals(&id).await.len()
                        );

                        // And same should happen when proposal is in pending commit
                        alice_central.context.commit_pending_proposals(&id).await.unwrap();
                        assert!(alice_central.pending_commit(&id).await.is_some());
                        let commit = bob_central.context.update_keying_material(&id).await.unwrap().commit;
                        let proposals = alice_central
                            .context
                            .decrypt_message(&id, commit.to_bytes().unwrap())
                            .await
                            .unwrap()
                            .proposals;
                        // So Alice proposal should also be renewed
                        // It should also replace existing one
                        assert_eq!(alice_central.pending_proposals(&id).await.len(), 1);
                        assert_eq!(
                            proposals.len(),
                            alice_central.pending_proposals(&id).await.len()
                        );
                    })
                },
            )
            .await
        }

        #[apply(all_cred_cipher)]
        #[wasm_bindgen_test]
        pub async fn renews_pending_commit_when_valid_commit_doesnt_add_same(case: TestCase) {
            run_test_with_client_ids(
                case.clone(),
                ["alice", "bob", "charlie"],
                move |[mut alice_central, mut bob_central, charlie_central]| {
                    Box::pin(async move {
                        let id = conversation_id();
                        alice_central
                            .context
                            .new_conversation(&id, case.credential_type, case.cfg.clone())
                            .await
                            .unwrap();
                        alice_central
                            .invite_all(&case, &id, [&bob_central])
                            .await
                            .unwrap();

                        // Alice commits adding Charlie
                        let charlie = charlie_central.rand_key_package(&case).await;
                        alice_central
                            .context
                            .add_members_to_conversation(&id, vec![charlie])
                            .await
                            .unwrap();
                        assert!(alice_central.pending_commit(&id).await.is_some());

                        // But meanwhile Bob will create a commit
                        let commit = bob_central.context.update_keying_material(&id).await.unwrap().commit;
                        let proposals = alice_central
                            .context
                            .decrypt_message(&id, commit.to_bytes().unwrap())
                            .await
                            .unwrap()
                            .proposals;
                        // So Alice proposal should be renewed
                        assert_eq!(alice_central.pending_proposals(&id).await.len(), 1);
                        assert_eq!(
                            proposals.len(),
                            alice_central.pending_proposals(&id).await.len()
                        );
                    })
                },
            )
            .await
        }
    }

    mod remove {
        use super::*;

        #[apply(all_cred_cipher)]
        #[wasm_bindgen_test]
        pub async fn not_renewable_when_valid_commit_removes_same(case: TestCase) {
            run_test_with_client_ids(
                case.clone(),
                ["alice", "bob", "charlie"],
                move |[mut alice_central, mut bob_central, mut charlie_central]| {
                    Box::pin(async move {
                        let id = conversation_id();
                        alice_central
                            .context
                            .new_conversation(&id, case.credential_type, case.cfg.clone())
                            .await
                            .unwrap();
                        alice_central
                            .invite_all(&case, &id, [&bob_central, &charlie_central])
                            .await
                            .unwrap();

                        assert!(alice_central.pending_proposals(&id).await.is_empty());
                        alice_central
                            .context
                            .new_remove_proposal(&id, charlie_central.get_client_id().await)
                            .await
                            .unwrap();
                        assert_eq!(alice_central.pending_proposals(&id).await.len(), 1);

                        let commit = bob_central
                            .context
                            .remove_members_from_conversation(&id, &[charlie_central.get_client_id().await])
                            .await
                            .unwrap()
                            .commit;
                        let proposals = alice_central
                            .context
                            .decrypt_message(&id, commit.to_bytes().unwrap())
                            .await
                            .unwrap()
                            .proposals;
                        // Remove proposal is not renewed since commit does same
                        assert!(alice_central.pending_proposals(&id).await.is_empty());
                        assert_eq!(
                            proposals.len(),
                            alice_central.pending_proposals(&id).await.len()
                        );
                    })
                },
            )
            .await
        }

        #[apply(all_cred_cipher)]
        #[wasm_bindgen_test]
        pub async fn not_renewable_by_ref(case: TestCase) {
            run_test_with_client_ids(
                case.clone(),
                ["alice", "bob", "charlie"],
                move |[mut alice_central, mut bob_central, mut charlie_central]| {
                    Box::pin(async move {
                        let id = conversation_id();
                        alice_central
                            .context
                            .new_conversation(&id, case.credential_type, case.cfg.clone())
                            .await
                            .unwrap();
                        alice_central
                            .invite_all(&case, &id, [&bob_central, &charlie_central])
                            .await
                            .unwrap();

                        let proposal = bob_central
                            .context
                            .new_remove_proposal(&id, charlie_central.get_client_id().await)
                            .await
                            .unwrap()
                            .proposal;
                        assert!(alice_central.pending_proposals(&id).await.is_empty());
                        alice_central
                            .context
                            .decrypt_message(&id, proposal.to_bytes().unwrap())
                            .await
                            .unwrap();
                        assert_eq!(alice_central.pending_proposals(&id).await.len(), 1);

                        let commit = charlie_central
                            .context
                            .update_keying_material(&id)
                            .await
                            .unwrap()
                            .commit;
                        let proposals = alice_central
                            .context
                            .decrypt_message(&id, commit.to_bytes().unwrap())
                            .await
                            .unwrap()
                            .proposals;
                        // Remove proposal is not renewed since by ref
                        assert!(alice_central.pending_proposals(&id).await.is_empty());
                        assert_eq!(
                            proposals.len(),
                            alice_central.pending_proposals(&id).await.len()
                        );
                    })
                },
            )
            .await
        }

        #[apply(all_cred_cipher)]
        #[wasm_bindgen_test]
        pub async fn renewable_when_valid_commit_doesnt_remove_same(case: TestCase) {
            run_test_with_client_ids(
                case.clone(),
                ["alice", "bob", "charlie", "debbie"],
                move |[mut alice_central, mut bob_central, mut charlie_central, mut debbie_central]| {
                    Box::pin(async move {
                        let id = conversation_id();
                        alice_central
                            .context
                            .new_conversation(&id, case.credential_type, case.cfg.clone())
                            .await
                            .unwrap();
                        alice_central
                            .invite_all(
                                &case,
                                &id,
                                [
                                    &bob_central,
                                    &charlie_central,
                                    &debbie_central,
                                ],
                            )
                            .await
                            .unwrap();

                        // Alice wants to remove Charlie
                        assert!(alice_central.pending_proposals(&id).await.is_empty());
                        alice_central
                            .context
                            .new_remove_proposal(&id, charlie_central.get_client_id().await)
                            .await
                            .unwrap();
                        assert_eq!(alice_central.pending_proposals(&id).await.len(), 1);

                        // Whereas Bob wants to remove Debbie
                        let commit = bob_central
                            .context
                            .remove_members_from_conversation(&id, &[debbie_central.get_client_id().await])
                            .await
                            .unwrap()
                            .commit;
                        let proposals = alice_central
                            .context
                            .decrypt_message(&id, commit.to_bytes().unwrap())
                            .await
                            .unwrap()
                            .proposals;
                        // Remove is renewed since valid commit removes another
                        assert_eq!(alice_central.pending_proposals(&id).await.len(), 1);
                        assert_eq!(
                            proposals.len(),
                            alice_central.pending_proposals(&id).await.len()
                        );
                    })
                },
            )
            .await
        }

        #[apply(all_cred_cipher)]
        #[wasm_bindgen_test]
        pub async fn renews_pending_commit_when_commit_doesnt_remove_same(case: TestCase) {
            run_test_with_client_ids(
                case.clone(),
                ["alice", "bob", "charlie", "debbie"],
                move |[mut alice_central, mut bob_central, mut charlie_central, mut debbie_central]| {
                    Box::pin(async move {
                        let id = conversation_id();
                        alice_central
                            .context
                            .new_conversation(&id, case.credential_type, case.cfg.clone())
                            .await
                            .unwrap();
                        alice_central
                            .invite_all(
                                &case,
                                &id,
                                [
                                    &bob_central,
                                    &charlie_central,
                                    &debbie_central,
                                ],
                            )
                            .await
                            .unwrap();

                        // Alice wants to remove Charlie
                        alice_central
                            .context
                            .remove_members_from_conversation(&id, &[charlie_central.get_client_id().await])
                            .await
                            .unwrap();
                        assert!(alice_central.pending_commit(&id).await.is_some());

                        // Whereas Bob wants to remove Debbie
                        let commit = bob_central
                            .context
                            .remove_members_from_conversation(&id, &[debbie_central.get_client_id().await])
                            .await
                            .unwrap()
                            .commit;
                        let proposals = alice_central
                            .context
                            .decrypt_message(&id, commit.to_bytes().unwrap())
                            .await
                            .unwrap()
                            .proposals;
                        // Remove is renewed since valid commit removes another
                        assert_eq!(alice_central.pending_proposals(&id).await.len(), 1);
                        assert_eq!(
                            proposals.len(),
                            alice_central.pending_proposals(&id).await.len()
                        );
                    })
                },
            )
            .await
        }

        #[apply(all_cred_cipher)]
        #[wasm_bindgen_test]
        pub async fn renews_pending_commit_from_proposal_when_commit_doesnt_remove_same(case: TestCase) {
            run_test_with_client_ids(
                case.clone(),
                ["alice", "bob", "charlie", "debbie"],
                move |[mut alice_central, mut bob_central, mut charlie_central, mut debbie_central]| {
                    Box::pin(async move {
                        let id = conversation_id();
                        alice_central
                            .context
                            .new_conversation(&id, case.credential_type, case.cfg.clone())
                            .await
                            .unwrap();
                        alice_central
                            .invite_all(
                                &case,
                                &id,
                                [
                                    &bob_central,
                                    &charlie_central,
                                    &debbie_central,
                                ],
                            )
                            .await
                            .unwrap();

                        // Alice wants to remove Charlie
                        alice_central
                            .context
                            .new_remove_proposal(&id, charlie_central.get_client_id().await)
                            .await
                            .unwrap();
                        alice_central.context.commit_pending_proposals(&id).await.unwrap();
                        assert_eq!(alice_central.pending_proposals(&id).await.len(), 1);
                        assert!(alice_central.pending_commit(&id).await.is_some());

                        // Whereas Bob wants to remove Debbie
                        let commit = bob_central
                            .context
                            .remove_members_from_conversation(&id, &[debbie_central.get_client_id().await])
                            .await
                            .unwrap()
                            .commit;
                        let proposals = alice_central
                            .context
                            .decrypt_message(&id, commit.to_bytes().unwrap())
                            .await
                            .unwrap()
                            .proposals;
                        // Remove is renewed since valid commit removes another
                        assert_eq!(alice_central.pending_proposals(&id).await.len(), 1);
                        assert_eq!(
                            proposals.len(),
                            alice_central.pending_proposals(&id).await.len()
                        );
                    })
                },
            )
            .await
        }
    }
}
