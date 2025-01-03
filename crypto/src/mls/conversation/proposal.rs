//! This table summarizes when a MLS group can create a commit or proposal:
//!
//! | can create handshake ? | 0 pend. Commit | 1 pend. Commit |
//! |------------------------|----------------|----------------|
//! | 0 pend. Proposal       | ✅              | ❌              |
//! | 1+ pend. Proposal      | ✅              | ❌              |

use mls_crypto_provider::MlsCryptoProvider;
use openmls::{binary_tree::LeafNodeIndex, framing::MlsMessageOut, key_packages::KeyPackageIn, prelude::LeafNode};

use super::{Error, Result};
use crate::context::CentralContext;
use crate::{
    e2e_identity::init_certificates::NewCrlDistributionPoint,
    mls::credential::crl::{extract_crl_uris_from_credentials, get_new_crl_distribution_points},
    prelude::{Client, MlsConversation},
    MlsError, MlsTransportResponse, RecursiveError,
};

/// Sending proposals
impl CentralContext {
    pub(crate) async fn send_and_merge_or_discard_proposal(
        &self,
        conversation: &mut MlsConversation,
        proposal: MlsMessageOut,
    ) -> Result<()> {
        let guard = self
            .mls_transport()
            .await
            .map_err(RecursiveError::root("getting mls transport"))?;
        let transport = guard.as_ref().ok_or::<Error>(
            RecursiveError::root("getting mls transport")(crate::Error::MlsTransportNotProvided).into(),
        )?;
        match transport
            .send_message(
                proposal
                    .to_bytes()
                    .map_err(MlsError::wrap("constructing byte vector of proposal"))?,
            )
            .await
            .map_err(RecursiveError::root("sending mls message"))?
        {
            MlsTransportResponse::Success => Ok(()),
            MlsTransportResponse::Abort { reason } => {
                self.clear_all_pending_proposals(conversation).await?;
                Err(Error::MessageRejected { reason })
            }
            MlsTransportResponse::Retry => self.commit_pending_proposals(conversation.id()).await,
        }
    }

    /// If there was a proper way to clear all proposals at once, this wouldn't be needed.
    /// However, `group.clear_pending_proposals()` in openmls doesn't delete the encryption keys of update proposals.
    /// So we have to delete them one by one.
    async fn clear_all_pending_proposals(&self, conversation: &mut MlsConversation) -> Result<()> {
        let proposal_refs: Vec<_> = {
            // clone the refs here to avoid borrowing `conversation` for the whole scope,
            // because we need a mutable reference to the group below.
            conversation
                .group
                .pending_proposals()
                .map(|p| p.proposal_reference())
                .cloned()
                .collect()
        };

        let keystore = &self
            .keystore()
            .await
            .map_err(RecursiveError::root("getting keystore"))?;

        for proposal_ref in proposal_refs {
            conversation
                .group
                .remove_pending_proposal(keystore, &proposal_ref)
                .await
                .map_err(MlsError::wrap("removing pending proposal"))?;
        }

        conversation
            .persist_group_when_changed(
                &self
                    .keystore()
                    .await
                    .map_err(RecursiveError::root("getting keystore"))?,
                true,
            )
            .await
    }
}

/// Creating proposals
impl MlsConversation {
    /// see [openmls::group::MlsGroup::propose_add_member]
    #[cfg_attr(test, crate::durable)]
    pub(crate) async fn propose_add_member(
        &mut self,
        client: &Client,
        backend: &MlsCryptoProvider,
        key_package: KeyPackageIn,
    ) -> Result<(MlsMessageOut, NewCrlDistributionPoint)> {
        let signer = &self
            .find_current_credential_bundle(client)
            .await
            .map_err(|_| Error::IdentityInitializationError)?
            .signature_key;

        let crl_new_distribution_points = get_new_crl_distribution_points(
            backend,
            extract_crl_uris_from_credentials(std::iter::once(key_package.credential().mls_credential()))
                .map_err(RecursiveError::mls_credential("extracting crl uris from credentials"))?,
        )
        .await
        .map_err(RecursiveError::mls_credential("getting new crl distribution points"))?;

        let (proposal, _) = self
            .group
            .propose_add_member(backend, signer, key_package)
            .await
            .map_err(MlsError::wrap("propose add member"))?;
        self.persist_group_when_changed(&backend.keystore(), false).await?;
        Ok((proposal, crl_new_distribution_points))
    }

    /// see [openmls::group::MlsGroup::propose_remove_member]
    #[cfg_attr(test, crate::durable)]
    pub(crate) async fn propose_remove_member(
        &mut self,
        client: &Client,
        backend: &MlsCryptoProvider,
        member: LeafNodeIndex,
    ) -> Result<MlsMessageOut> {
        let signer = &self
            .find_current_credential_bundle(client)
            .await
            .map_err(|_| Error::IdentityInitializationError)?
            .signature_key;
        let (proposal, _) = self
            .group
            .propose_remove_member(backend, signer, member)
            .map_err(MlsError::wrap("propose remove member"))?;
        self.persist_group_when_changed(&backend.keystore(), false).await?;
        Ok(proposal)
    }

    /// see [openmls::group::MlsGroup::propose_self_update]
    #[cfg_attr(test, crate::durable)]
    pub(crate) async fn propose_self_update(
        &mut self,
        client: &Client,
        backend: &MlsCryptoProvider,
    ) -> Result<MlsMessageOut> {
        self.propose_explicit_self_update(client, backend, None).await
    }

    /// see [openmls::group::MlsGroup::propose_self_update]
    #[cfg_attr(test, crate::durable)]
    pub(crate) async fn propose_explicit_self_update(
        &mut self,
        client: &Client,
        backend: &MlsCryptoProvider,
        leaf_node: Option<LeafNode>,
    ) -> Result<MlsMessageOut> {
        let msg_signer = &self
            .find_current_credential_bundle(client)
            .await
            .map_err(|_| Error::IdentityInitializationError)?
            .signature_key;

        let (proposal, _) = if let Some(leaf_node) = leaf_node {
            let leaf_node_signer = &self
                .find_most_recent_credential_bundle(client)
                .await
                .map_err(RecursiveError::mls_client("finding most recent credential bundle"))?
                .signature_key;

            self.group
                .propose_explicit_self_update(backend, msg_signer, leaf_node, leaf_node_signer)
                .await
        } else {
            self.group.propose_self_update(backend, msg_signer).await
        }
        .map_err(MlsError::wrap("proposing self update"))?;

        self.persist_group_when_changed(&backend.keystore(), false).await?;
        Ok(proposal)
    }
}

#[cfg(test)]
mod tests {
    use itertools::Itertools;
    use openmls::prelude::SignaturePublicKey;
    use wasm_bindgen_test::*;

    use crate::test_utils::*;

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
                move |[mut alice_central, bob_central, mut charlie_central]| {
                    Box::pin(async move {
                        let id = conversation_id();
                        alice_central
                            .context
                            .new_conversation(&id, case.credential_type, case.cfg.clone())
                            .await
                            .unwrap();
                        alice_central.invite_all(&case, &id, [&bob_central]).await.unwrap();
                        let charlie_kp = charlie_central.get_one_key_package(&case).await;

                        assert!(alice_central.pending_proposals(&id).await.is_empty());
                        alice_central.context.new_add_proposal(&id, charlie_kp).await.unwrap();
                        assert_eq!(alice_central.pending_proposals(&id).await.len(), 1);
                        let proposal = alice_central.mls_transport.latest_message().await;
                        bob_central.context.decrypt_message(&id, proposal).await.unwrap();
                        bob_central.context.commit_pending_proposals(&id).await.unwrap();
                        let commit = bob_central.mls_transport.latest_commit().await;
                        let welcome = bob_central.mls_transport.latest_welcome_message().await;
                        assert_eq!(bob_central.get_conversation_unchecked(&id).await.members().len(), 3);

                        // if 'new_proposal' wasn't durable this would fail because proposal would
                        // not be referenced in commit
                        alice_central
                            .context
                            .decrypt_message(&id, commit.to_bytes().unwrap())
                            .await
                            .unwrap();
                        assert_eq!(alice_central.get_conversation_unchecked(&id).await.members().len(), 3);

                        charlie_central
                            .try_join_from_welcome(
                                &id,
                                welcome.into(),
                                case.custom_cfg(),
                                vec![&alice_central, &bob_central],
                            )
                            .await
                            .unwrap();
                        assert_eq!(charlie_central.get_conversation_unchecked(&id).await.members().len(), 3);
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
                move |[mut alice_central, bob_central, charlie_central]| {
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
                        let proposal = alice_central.mls_transport.latest_message().await;
                        assert_eq!(alice_central.pending_proposals(&id).await.len(), 1);
                        bob_central.context.decrypt_message(&id, &proposal).await.unwrap();
                        bob_central.context.commit_pending_proposals(&id).await.unwrap();
                        let commit = bob_central.mls_transport.latest_commit().await;
                        assert_eq!(bob_central.get_conversation_unchecked(&id).await.members().len(), 2);

                        // if 'new_proposal' wasn't durable this would fail because proposal would
                        // not be referenced in commit
                        alice_central
                            .context
                            .decrypt_message(&id, commit.to_bytes().unwrap())
                            .await
                            .unwrap();
                        assert_eq!(alice_central.get_conversation_unchecked(&id).await.members().len(), 2);
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
            run_test_with_client_ids(case.clone(), ["alice", "bob"], move |[alice_central, bob_central]| {
                Box::pin(async move {
                    let id = conversation_id();
                    alice_central
                        .context
                        .new_conversation(&id, case.credential_type, case.cfg.clone())
                        .await
                        .unwrap();
                    alice_central.invite_all(&case, &id, [&bob_central]).await.unwrap();

                    let bob_keys = bob_central
                        .get_conversation_unchecked(&id)
                        .await
                        .signature_keys()
                        .collect::<Vec<SignaturePublicKey>>();
                    let alice_keys = alice_central
                        .get_conversation_unchecked(&id)
                        .await
                        .signature_keys()
                        .collect::<Vec<SignaturePublicKey>>();
                    assert!(alice_keys.iter().all(|a_key| bob_keys.contains(a_key)));
                    let alice_key = alice_central
                        .encryption_key_of(&id, alice_central.get_client_id().await)
                        .await;

                    alice_central.context.new_update_proposal(&id).await.unwrap();
                    let proposal = alice_central.mls_transport.latest_message().await;
                    bob_central.context.decrypt_message(&id, proposal).await.unwrap();
                    bob_central.context.commit_pending_proposals(&id).await.unwrap();
                    let commit = bob_central.mls_transport.latest_commit().await;

                    assert!(!bob_central
                        .get_conversation_unchecked(&id)
                        .await
                        .encryption_keys()
                        .contains(&alice_key));

                    assert!(alice_central
                        .get_conversation_unchecked(&id)
                        .await
                        .encryption_keys()
                        .contains(&alice_key));
                    // if 'new_proposal' wasn't durable this would fail because proposal would
                    // not be referenced in commit
                    alice_central
                        .context
                        .decrypt_message(&id, commit.to_bytes().unwrap())
                        .await
                        .unwrap();
                    assert!(!alice_central
                        .get_conversation_unchecked(&id)
                        .await
                        .encryption_keys()
                        .contains(&alice_key));

                    // ensuring both can encrypt messages
                    assert!(alice_central.try_talk_to(&id, &bob_central).await.is_ok());
                })
            })
            .await;
        }
    }

    mod delivery_semantics {
        use super::*;

        #[apply(all_cred_cipher)]
        #[wasm_bindgen_test]
        async fn should_prevent_out_of_order_proposals(case: TestCase) {
            run_test_with_client_ids(case.clone(), ["alice", "bob"], move |[alice_central, bob_central]| {
                Box::pin(async move {
                    let id = conversation_id();
                    alice_central
                        .context
                        .new_conversation(&id, case.credential_type, case.cfg.clone())
                        .await
                        .unwrap();
                    alice_central.invite_all(&case, &id, [&bob_central]).await.unwrap();

                    alice_central.context.new_update_proposal(&id).await.unwrap();
                    let proposal = alice_central.mls_transport.latest_message().await;

                    bob_central.context.decrypt_message(&id, &proposal).await.unwrap();
                    bob_central.context.commit_pending_proposals(&id).await.unwrap();
                    // epoch++

                    // fails when we try to decrypt a proposal for past epoch
                    let past_proposal = bob_central.context.decrypt_message(&id, &proposal).await;
                    assert!(matches!(past_proposal.unwrap_err(), Error::StaleProposal));
                })
            })
            .await;
        }
    }
}
