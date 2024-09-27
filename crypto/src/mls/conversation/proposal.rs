//! This table summarizes when a MLS group can create a commit or proposal:
//!
//! | can create handshake ? | 0 pend. Commit | 1 pend. Commit |
//! |------------------------|----------------|----------------|
//! | 0 pend. Proposal       | ✅              | ❌              |
//! | 1+ pend. Proposal      | ✅              | ❌              |

use openmls::{binary_tree::LeafNodeIndex, framing::MlsMessageOut, key_packages::KeyPackageIn, prelude::LeafNode};

use mls_crypto_provider::TransactionalCryptoProvider;

use crate::{
    e2e_identity::init_certificates::NewCrlDistributionPoint, mls::credential::crl::get_new_crl_distribution_points,
};
use crate::{
    mls::credential::crl::extract_crl_uris_from_credentials,
    prelude::{Client, MlsConversation, MlsProposalRef},
    CryptoError, CryptoResult, MlsError,
};

/// Creating proposals
impl MlsConversation {
    /// see [openmls::group::MlsGroup::propose_add_member]
    #[cfg_attr(test, crate::durable)]
    pub async fn propose_add_member(
        &mut self,
        client: &Client,
        backend: &TransactionalCryptoProvider,
        key_package: KeyPackageIn,
    ) -> CryptoResult<MlsProposalBundle> {
        let signer = &self
            .find_current_credential_bundle(client)?
            .ok_or(CryptoError::IdentityInitializationError)?
            .signature_key;

        let crl_new_distribution_points = get_new_crl_distribution_points(
            backend,
            extract_crl_uris_from_credentials(std::iter::once(key_package.credential().mls_credential()))?,
        )
        .await?;

        let (proposal, proposal_ref) = self
            .group
            .propose_add_member(backend, signer, key_package)
            .await
            .map_err(MlsError::from)?;
        let proposal = MlsProposalBundle {
            proposal,
            proposal_ref: proposal_ref.into(),
            crl_new_distribution_points,
        };
        self.persist_group_when_changed(&backend.transaction(), false).await?;
        Ok(proposal)
    }

    /// see [openmls::group::MlsGroup::propose_remove_member]
    #[cfg_attr(test, crate::durable)]
    pub async fn propose_remove_member(
        &mut self,
        client: &Client,
        backend: &TransactionalCryptoProvider,
        member: LeafNodeIndex,
    ) -> CryptoResult<MlsProposalBundle> {
        let signer = &self
            .find_current_credential_bundle(client)?
            .ok_or(CryptoError::IdentityInitializationError)?
            .signature_key;
        let proposal = self
            .group
            .propose_remove_member(backend, signer, member)
            .map_err(MlsError::from)
            .map_err(CryptoError::from)
            .map(MlsProposalBundle::from)?;
        self.persist_group_when_changed(&backend.transaction(), false).await?;
        Ok(proposal)
    }

    /// see [openmls::group::MlsGroup::propose_self_update]
    #[cfg_attr(test, crate::durable)]
    pub async fn propose_self_update(
        &mut self,
        client: &Client,
        backend: &TransactionalCryptoProvider,
    ) -> CryptoResult<MlsProposalBundle> {
        self.propose_explicit_self_update(client, backend, None).await
    }

    /// see [openmls::group::MlsGroup::propose_self_update]
    #[cfg_attr(test, crate::durable)]
    pub async fn propose_explicit_self_update(
        &mut self,
        client: &Client,
        backend: &TransactionalCryptoProvider,
        leaf_node: Option<LeafNode>,
    ) -> CryptoResult<MlsProposalBundle> {
        let msg_signer = &self
            .find_current_credential_bundle(client)?
            .ok_or(CryptoError::IdentityInitializationError)?
            .signature_key;

        let proposal = if let Some(leaf_node) = leaf_node {
            let leaf_node_signer = &self
                .find_most_recent_credential_bundle(client)?
                .ok_or(CryptoError::IdentityInitializationError)?
                .signature_key;

            self.group
                .propose_explicit_self_update(backend, msg_signer, leaf_node, leaf_node_signer)
                .await
        } else {
            self.group.propose_self_update(backend, msg_signer).await
        }
        .map_err(MlsError::from)
        .map(MlsProposalBundle::from)?;

        self.persist_group_when_changed(&backend.transaction(), false).await?;
        Ok(proposal)
    }
}

/// Returned when a Proposal is created. Helps roll backing a local proposal
#[derive(Debug)]
pub struct MlsProposalBundle {
    /// The proposal message
    pub proposal: MlsMessageOut,
    /// A unique identifier of the proposal to rollback it later if required
    pub proposal_ref: MlsProposalRef,
    /// New CRL distribution points that appeared by the introduction of a new credential
    pub crl_new_distribution_points: NewCrlDistributionPoint,
}

impl From<(MlsMessageOut, openmls::prelude::hash_ref::ProposalRef)> for MlsProposalBundle {
    fn from((proposal, proposal_ref): (MlsMessageOut, openmls::prelude::hash_ref::ProposalRef)) -> Self {
        Self {
            proposal,
            proposal_ref: proposal_ref.into(),
            crl_new_distribution_points: None.into(),
        }
    }
}

impl MlsProposalBundle {
    /// Serializes both wrapped objects into TLS and return them as a tuple of byte arrays.
    /// 0 -> proposal
    /// 1 -> proposal reference
    #[allow(clippy::type_complexity)]
    pub fn to_bytes(self) -> CryptoResult<(Vec<u8>, Vec<u8>, NewCrlDistributionPoint)> {
        use openmls::prelude::TlsSerializeTrait as _;
        let proposal = self.proposal.tls_serialize_detached().map_err(MlsError::from)?;
        let proposal_ref = self.proposal_ref.to_bytes();

        Ok((proposal, proposal_ref, self.crl_new_distribution_points))
    }
}

#[cfg(test)]
mod tests {
    use itertools::Itertools;
    use openmls::prelude::SignaturePublicKey;
    use wasm_bindgen_test::*;

    use crate::{prelude::MlsCommitBundle, test_utils::*};

    use super::*;

    wasm_bindgen_test_configure!(run_in_browser);

    mod propose_add_members {
        use super::*;

        #[apply(all_cred_cipher)]
        #[wasm_bindgen_test]
        async fn can_propose_adding_members_to_conversation(case: TestCase) {
            run_test_with_client_ids(
                case.clone(),
                ["alice", "bob", "charlie"],
                move |[mut alice_central, mut bob_central, mut charlie_central]| {
                    Box::pin(async move {
                        let id = conversation_id();
                        alice_central
                            .mls_central
                            .new_conversation(&id, case.credential_type, case.cfg.clone())
                            .await
                            .unwrap();
                        alice_central
                            .mls_central
                            .invite_all(&case, &id, [&mut bob_central.mls_central])
                            .await
                            .unwrap();
                        let charlie_kp = charlie_central.mls_central.get_one_key_package(&case).await;

                        assert!(alice_central.mls_central.pending_proposals(&id).await.is_empty());
                        let proposal = alice_central
                            .mls_central
                            .new_add_proposal(&id, charlie_kp)
                            .await
                            .unwrap()
                            .proposal;
                        assert_eq!(alice_central.mls_central.pending_proposals(&id).await.len(), 1);
                        bob_central
                            .mls_central
                            .decrypt_message(&id, proposal.to_bytes().unwrap())
                            .await
                            .unwrap();
                        let MlsCommitBundle { commit, welcome, .. } = bob_central
                            .mls_central
                            .commit_pending_proposals(&id)
                            .await
                            .unwrap()
                            .unwrap();
                        bob_central.mls_central.commit_accepted(&id).await.unwrap();
                        assert_eq!(
                            bob_central
                                .mls_central
                                .get_conversation_unchecked(&id)
                                .await
                                .members()
                                .len(),
                            3
                        );

                        // if 'new_proposal' wasn't durable this would fail because proposal would
                        // not be referenced in commit
                        alice_central
                            .mls_central
                            .decrypt_message(&id, commit.to_bytes().unwrap())
                            .await
                            .unwrap();
                        assert_eq!(
                            alice_central
                                .mls_central
                                .get_conversation_unchecked(&id)
                                .await
                                .members()
                                .len(),
                            3
                        );

                        charlie_central
                            .mls_central
                            .try_join_from_welcome(
                                &id,
                                welcome.unwrap().into(),
                                case.custom_cfg(),
                                vec![&mut alice_central.mls_central, &mut bob_central.mls_central],
                            )
                            .await
                            .unwrap();
                        assert_eq!(
                            charlie_central
                                .mls_central
                                .get_conversation_unchecked(&id)
                                .await
                                .members()
                                .len(),
                            3
                        );
                    })
                },
            )
            .await
        }
    }

    mod propose_remove_members {
        use super::*;

        #[apply(all_cred_cipher)]
        #[wasm_bindgen_test]
        async fn can_propose_removing_members_from_conversation(case: TestCase) {
            run_test_with_client_ids(
                case.clone(),
                ["alice", "bob", "charlie"],
                move |[mut alice_central, mut bob_central, mut charlie_central]| {
                    Box::pin(async move {
                        let id = conversation_id();
                        alice_central
                            .mls_central
                            .new_conversation(&id, case.credential_type, case.cfg.clone())
                            .await
                            .unwrap();
                        alice_central
                            .mls_central
                            .invite_all(
                                &case,
                                &id,
                                [&mut bob_central.mls_central, &mut charlie_central.mls_central],
                            )
                            .await
                            .unwrap();

                        assert!(alice_central.mls_central.pending_proposals(&id).await.is_empty());
                        let proposal = alice_central
                            .mls_central
                            .new_remove_proposal(&id, charlie_central.mls_central.get_client_id())
                            .await
                            .unwrap()
                            .proposal;
                        assert_eq!(alice_central.mls_central.pending_proposals(&id).await.len(), 1);
                        bob_central
                            .mls_central
                            .decrypt_message(&id, proposal.to_bytes().unwrap())
                            .await
                            .unwrap();
                        let commit = bob_central
                            .mls_central
                            .commit_pending_proposals(&id)
                            .await
                            .unwrap()
                            .unwrap()
                            .commit;
                        bob_central.mls_central.commit_accepted(&id).await.unwrap();
                        assert_eq!(
                            bob_central
                                .mls_central
                                .get_conversation_unchecked(&id)
                                .await
                                .members()
                                .len(),
                            2
                        );

                        // if 'new_proposal' wasn't durable this would fail because proposal would
                        // not be referenced in commit
                        alice_central
                            .mls_central
                            .decrypt_message(&id, commit.to_bytes().unwrap())
                            .await
                            .unwrap();
                        assert_eq!(
                            alice_central
                                .mls_central
                                .get_conversation_unchecked(&id)
                                .await
                                .members()
                                .len(),
                            2
                        );
                    })
                },
            )
            .await
        }
    }

    mod propose_self_update {
        use super::*;

        #[apply(all_cred_cipher)]
        #[wasm_bindgen_test]
        async fn can_propose_updating(case: TestCase) {
            run_test_with_client_ids(
                case.clone(),
                ["alice", "bob"],
                move |[mut alice_central, mut bob_central]| {
                    Box::pin(async move {
                        let id = conversation_id();
                        alice_central
                            .mls_central
                            .new_conversation(&id, case.credential_type, case.cfg.clone())
                            .await
                            .unwrap();
                        alice_central
                            .mls_central
                            .invite_all(&case, &id, [&mut bob_central.mls_central])
                            .await
                            .unwrap();

                        let bob_keys = bob_central
                            .mls_central
                            .get_conversation_unchecked(&id)
                            .await
                            .signature_keys()
                            .collect::<Vec<SignaturePublicKey>>();
                        let alice_keys = alice_central
                            .mls_central
                            .get_conversation_unchecked(&id)
                            .await
                            .signature_keys()
                            .collect::<Vec<SignaturePublicKey>>();
                        assert!(alice_keys.iter().all(|a_key| bob_keys.contains(a_key)));
                        let alice_key = alice_central
                            .mls_central
                            .encryption_key_of(&id, alice_central.mls_central.get_client_id())
                            .await;

                        let proposal = alice_central
                            .mls_central
                            .new_update_proposal(&id)
                            .await
                            .unwrap()
                            .proposal;
                        bob_central
                            .mls_central
                            .decrypt_message(&id, proposal.to_bytes().unwrap())
                            .await
                            .unwrap();
                        let commit = bob_central
                            .mls_central
                            .commit_pending_proposals(&id)
                            .await
                            .unwrap()
                            .unwrap()
                            .commit;

                        // before merging, commit is not applied
                        assert!(bob_central
                            .mls_central
                            .get_conversation_unchecked(&id)
                            .await
                            .encryption_keys()
                            .contains(&alice_key));
                        bob_central.mls_central.commit_accepted(&id).await.unwrap();
                        assert!(!bob_central
                            .mls_central
                            .get_conversation_unchecked(&id)
                            .await
                            .encryption_keys()
                            .contains(&alice_key));

                        assert!(alice_central
                            .mls_central
                            .get_conversation_unchecked(&id)
                            .await
                            .encryption_keys()
                            .contains(&alice_key));
                        // if 'new_proposal' wasn't durable this would fail because proposal would
                        // not be referenced in commit
                        alice_central
                            .mls_central
                            .decrypt_message(&id, commit.to_bytes().unwrap())
                            .await
                            .unwrap();
                        assert!(!alice_central
                            .mls_central
                            .get_conversation_unchecked(&id)
                            .await
                            .encryption_keys()
                            .contains(&alice_key));

                        // ensuring both can encrypt messages
                        assert!(alice_central
                            .mls_central
                            .try_talk_to(&id, &mut bob_central.mls_central)
                            .await
                            .is_ok());
                    })
                },
            )
            .await;
        }
    }

    mod delivery_semantics {
        use super::*;

        #[apply(all_cred_cipher)]
        #[wasm_bindgen_test]
        async fn should_prevent_out_of_order_proposals(case: TestCase) {
            run_test_with_client_ids(
                case.clone(),
                ["alice", "bob"],
                move |[mut alice_central, mut bob_central]| {
                    Box::pin(async move {
                        let id = conversation_id();
                        alice_central
                            .mls_central
                            .new_conversation(&id, case.credential_type, case.cfg.clone())
                            .await
                            .unwrap();
                        alice_central
                            .mls_central
                            .invite_all(&case, &id, [&mut bob_central.mls_central])
                            .await
                            .unwrap();

                        let proposal = alice_central
                            .mls_central
                            .new_update_proposal(&id)
                            .await
                            .unwrap()
                            .proposal;

                        bob_central
                            .mls_central
                            .decrypt_message(&id, &proposal.to_bytes().unwrap())
                            .await
                            .unwrap();
                        bob_central.mls_central.commit_pending_proposals(&id).await.unwrap();
                        // epoch++
                        bob_central.mls_central.commit_accepted(&id).await.unwrap();

                        // fails when we try to decrypt a proposal for past epoch
                        let past_proposal = bob_central
                            .mls_central
                            .decrypt_message(&id, &proposal.to_bytes().unwrap())
                            .await;
                        assert!(matches!(past_proposal.unwrap_err(), CryptoError::StaleProposal));
                    })
                },
            )
            .await;
        }
    }
}
