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

use core_crypto_keystore::entities::{MlsEncryptionKeyPair, MlsPendingMessage};
use openmls::prelude::MlsGroupStateError;
use openmls_traits::OpenMlsCryptoProvider;

use mls_crypto_provider::TransactionalCryptoProvider;

use crate::{
    mls::{context::CentralContext, ConversationId, MlsConversation},
    prelude::{decrypt::MlsBufferedConversationDecryptMessage, MlsProposalRef},
    CryptoError, CryptoResult, MlsError,
};

/// Abstraction over a MLS group capable of merging a commit
impl MlsConversation {
    /// see [MlsCentral::commit_accepted]
    #[cfg_attr(test, crate::durable)]
    #[cfg_attr(not(test), tracing::instrument(err, skip_all))]
    pub async fn commit_accepted(&mut self, backend: &TransactionalCryptoProvider) -> CryptoResult<()> {
        // openmls stores here all the encryption keypairs used for update proposals..
        let previous_own_leaf_nodes = self.group.own_leaf_nodes.clone();

        self.group.merge_pending_commit(backend).await.map_err(MlsError::from)?;
        self.persist_group_when_changed(&backend.keystore(), false).await?;

        // ..so if there's any, we clear them after the commit is merged
        for oln in &previous_own_leaf_nodes {
            let ek = oln.encryption_key().as_slice();
            let _ = backend.key_store().remove::<MlsEncryptionKeyPair, _>(ek).await;
        }

        Ok(())
    }

    /// see [MlsCentral::clear_pending_proposal]
    #[cfg_attr(test, crate::durable)]
    #[cfg_attr(not(test), tracing::instrument(err, skip_all))]
    pub async fn clear_pending_proposal(
        &mut self,
        proposal_ref: MlsProposalRef,
        backend: &TransactionalCryptoProvider,
    ) -> CryptoResult<()> {
        self.group
            .remove_pending_proposal(backend.key_store(), &proposal_ref)
            .await
            .map_err(|e| match e {
                MlsGroupStateError::PendingProposalNotFound => CryptoError::PendingProposalNotFound(proposal_ref),
                _ => CryptoError::from(MlsError::from(e)),
            })?;
        self.persist_group_when_changed(&backend.keystore(), true).await?;
        Ok(())
    }

    /// see [MlsCentral::clear_pending_commit]
    #[cfg_attr(test, crate::durable)]
    #[cfg_attr(not(test), tracing::instrument(err, skip_all))]
    pub async fn clear_pending_commit(&mut self, backend: &TransactionalCryptoProvider) -> CryptoResult<()> {
        if self.group.pending_commit().is_some() {
            self.group.clear_pending_commit();
            self.persist_group_when_changed(&backend.keystore(), true).await?;
            Ok(())
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
impl CentralContext {
    /// The commit we created has been accepted by the Delivery Service. Hence it is guaranteed
    /// to be used for the new epoch.
    /// We can now safely "merge" it (effectively apply the commit to the group) and update it
    /// in the keystore. The previous can be discarded to respect Forward Secrecy.
    #[cfg_attr(not(test), tracing::instrument(err, skip_all))]
    pub async fn commit_accepted(
        &self,
        id: &ConversationId,
    ) -> CryptoResult<Option<Vec<MlsBufferedConversationDecryptMessage>>> {
        let conv = self.get_conversation(id).await?;
        let mut conv = conv.write().await;
        conv.commit_accepted(&self.mls_provider().await?).await?;

        let pending_messages = self.restore_pending_messages(&mut conv, false).await?;
        if pending_messages.is_some() {
            self.keystore().await?.remove::<MlsPendingMessage, _>(id).await?;
        }
        Ok(pending_messages)
    }

    /// Allows to remove a pending (uncommitted) proposal. Use this when backend rejects the proposal
    /// you just sent e.g. if permissions have changed meanwhile.
    ///
    /// **CAUTION**: only use this when you had an explicit response from the Delivery Service
    /// e.g. 403 or 409. Do not use otherwise e.g. 5xx responses, timeout etc..
    ///
    /// # Arguments
    /// * `conversation_id` - the group/conversation id
    /// * `proposal_ref` - unique proposal identifier which is present in [crate::prelude::MlsProposalBundle] and
    /// returned from all operation creating a proposal
    ///
    /// # Errors
    /// When the conversation is not found or the proposal reference does not identify a proposal
    /// in the local pending proposal store
    #[cfg_attr(not(test), tracing::instrument(err, skip_all))]
    pub async fn clear_pending_proposal(
        &self,
        conversation_id: &ConversationId,
        proposal_ref: MlsProposalRef,
    ) -> CryptoResult<()> {
        self.get_conversation(conversation_id)
            .await?
            .write()
            .await
            .clear_pending_proposal(proposal_ref, &self.mls_provider().await?)
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
    #[cfg_attr(test, crate::idempotent)]
    #[cfg_attr(not(test), tracing::instrument(err, skip_all))]
    pub async fn clear_pending_commit(&self, conversation_id: &ConversationId) -> CryptoResult<()> {
        self.get_conversation(conversation_id)
            .await?
            .write()
            .await
            .clear_pending_commit(&self.mls_provider().await?)
            .await
    }
}

#[cfg(test)]
mod tests {
    use openmls::prelude::Proposal;
    use wasm_bindgen_test::*;

    use crate::test_utils::*;

    use super::*;

    wasm_bindgen_test_configure!(run_in_browser);

    mod commit_accepted {
        use super::*;

        #[apply(all_cred_cipher)]
        #[wasm_bindgen_test]
        async fn should_apply_pending_commit(case: TestCase) {
            run_test_with_client_ids(
                case.clone(),
                ["alice", "bob"],
                move |[alice_central, bob_central]| {
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
                        assert_eq!(
                            alice_central
                                .get_conversation_unchecked(&id)
                                .await
                                .members()
                                .len(),
                            2
                        );
                        alice_central
                            .context
                            .remove_members_from_conversation(&id, &[bob_central.get_client_id().await])
                            .await
                            .unwrap();
                        assert_eq!(
                            alice_central
                                .get_conversation_unchecked(&id)
                                .await
                                .members()
                                .len(),
                            2
                        );
                        alice_central.context.commit_accepted(&id).await.unwrap();
                        assert_eq!(
                            alice_central
                                .get_conversation_unchecked(&id)
                                .await
                                .members()
                                .len(),
                            1
                        );
                    })
                },
            )
            .await
        }

        #[apply(all_cred_cipher)]
        #[wasm_bindgen_test]
        async fn should_clear_pending_commit_and_proposals(case: TestCase) {
            run_test_with_client_ids(
                case.clone(),
                ["alice", "bob"],
                move |[mut alice_central, bob_central]| {
                    Box::pin(async move {
                        let id = conversation_id();
                        alice_central
                            .context
                            .new_conversation(&id, case.credential_type, case.cfg.clone())
                            .await
                            .unwrap();
                        alice_central.context.new_update_proposal(&id).await.unwrap();
                        let bob = bob_central.rand_key_package(&case).await;
                        alice_central
                            .context
                            .add_members_to_conversation(&id, vec![bob])
                            .await
                            .unwrap();
                        assert!(!alice_central.pending_proposals(&id).await.is_empty());
                        assert!(alice_central.pending_commit(&id).await.is_some());
                        alice_central.context.commit_accepted(&id).await.unwrap();
                        assert!(alice_central.pending_commit(&id).await.is_none());
                        assert!(alice_central.pending_proposals(&id).await.is_empty());
                    })
                },
            )
            .await
        }

        #[apply(all_cred_cipher)]
        #[wasm_bindgen_test]
        async fn should_clean_associated_key_material(case: TestCase) {
            run_test_with_client_ids(case.clone(), ["alice"], move |[alice_central]| {
                Box::pin(async move {
                    let id = conversation_id();
                    alice_central
                        .context
                        .new_conversation(&id, case.credential_type, case.cfg.clone())
                        .await
                        .unwrap();

                    let initial_count = alice_central.context.count_entities().await;

                    alice_central.context.new_update_proposal(&id).await.unwrap();
                    let post_proposal_count = alice_central.context.count_entities().await;
                    assert_eq!(
                        post_proposal_count.encryption_keypair,
                        initial_count.encryption_keypair + 1
                    );

                    alice_central.context.commit_pending_proposals(&id).await.unwrap();
                    alice_central.context.commit_accepted(&id).await.unwrap();

                    let final_count = alice_central.context.count_entities().await;
                    assert_eq!(initial_count, final_count);
                })
            })
            .await
        }
    }

    mod clear_pending_proposal {
        use super::*;

        #[apply(all_cred_cipher)]
        #[wasm_bindgen_test]
        pub async fn should_remove_proposal(case: TestCase) {
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
                            .invite_all(&case, &id, [&bob_central])
                            .await
                            .unwrap();
                        assert!(alice_central.pending_proposals(&id).await.is_empty());

                        let charlie_kp = charlie_central.get_one_key_package(&case).await;
                        let add_ref = alice_central
                            .context
                            .new_add_proposal(&id, charlie_kp)
                            .await
                            .unwrap()
                            .proposal_ref;

                        let remove_ref = alice_central
                            .context
                            .new_remove_proposal(&id, bob_central.get_client_id().await)
                            .await
                            .unwrap()
                            .proposal_ref;

                        let update_ref = alice_central
                            .context
                            .new_update_proposal(&id)
                            .await
                            .unwrap()
                            .proposal_ref;

                        assert_eq!(alice_central.pending_proposals(&id).await.len(), 3);
                        alice_central
                            .context
                            .clear_pending_proposal(&id, add_ref)
                            .await
                            .unwrap();
                        assert_eq!(alice_central.pending_proposals(&id).await.len(), 2);
                        assert!(!alice_central
                            .pending_proposals(&id)
                            .await
                            .into_iter()
                            .any(|p| matches!(p.proposal(), Proposal::Add(_))));

                        alice_central
                            .context
                            .clear_pending_proposal(&id, remove_ref)
                            .await
                            .unwrap();
                        assert_eq!(alice_central.pending_proposals(&id).await.len(), 1);
                        assert!(!alice_central
                            .pending_proposals(&id)
                            .await
                            .into_iter()
                            .any(|p| matches!(p.proposal(), Proposal::Remove(_))));

                        alice_central
                            .context
                            .clear_pending_proposal(&id, update_ref)
                            .await
                            .unwrap();
                        assert!(alice_central.pending_proposals(&id).await.is_empty());
                        assert!(!alice_central
                            .pending_proposals(&id)
                            .await
                            .into_iter()
                            .any(|p| matches!(p.proposal(), Proposal::Update(_))));
                    })
                },
            )
            .await
        }

        #[apply(all_cred_cipher)]
        #[wasm_bindgen_test]
        pub async fn should_fail_when_conversation_not_found(case: TestCase) {
            run_test_with_client_ids(case.clone(), ["alice"], move |[alice_central]| {
                Box::pin(async move {
                    let id = conversation_id();
                    let simple_ref = MlsProposalRef::from(vec![0; case.ciphersuite().hash_length()]);
                    let clear = alice_central.context.clear_pending_proposal(&id, simple_ref).await;
                    assert!(matches!(clear.unwrap_err(), CryptoError::ConversationNotFound(conv_id) if conv_id == id))
                })
            })
            .await
        }

        #[apply(all_cred_cipher)]
        #[wasm_bindgen_test]
        pub async fn should_fail_when_proposal_ref_not_found(case: TestCase) {
            run_test_with_client_ids(case.clone(), ["alice"], move |[mut alice_central]| {
                Box::pin(async move {
                    let id = conversation_id();
                    alice_central
                        .context.new_conversation(&id, case.credential_type, case.cfg.clone())
                        .await
                        .unwrap();
                    assert!(alice_central.pending_proposals(&id).await.is_empty());
                    let any_ref = MlsProposalRef::from(vec![0; case.ciphersuite().hash_length()]);
                    let clear = alice_central.context.clear_pending_proposal(&id, any_ref.clone()).await;
                    assert!(matches!(clear.unwrap_err(), CryptoError::PendingProposalNotFound(prop_ref) if prop_ref == any_ref))
                })
            })
            .await
        }

        #[apply(all_cred_cipher)]
        #[wasm_bindgen_test]
        pub async fn should_clean_associated_key_material(case: TestCase) {
            run_test_with_client_ids(case.clone(), ["alice"], move |[mut cc]| {
                Box::pin(async move {
                    let id = conversation_id();
                    cc.context
                        .new_conversation(&id, case.credential_type, case.cfg.clone())
                        .await
                        .unwrap();
                    assert!(cc.pending_proposals(&id).await.is_empty());

                    let init = cc.context.count_entities().await;

                    let proposal_ref = cc.context.new_update_proposal(&id).await.unwrap().proposal_ref;
                    assert_eq!(cc.pending_proposals(&id).await.len(), 1);

                    cc.context.clear_pending_proposal(&id, proposal_ref).await.unwrap();
                    assert!(cc.pending_proposals(&id).await.is_empty());

                    // This whole flow should be idempotent.
                    // Here we verify that we are indeed deleting the `EncryptionKeyPair` created
                    // for the Update proposal
                    let after_clear_proposal = cc.context.count_entities().await;
                    assert_eq!(init, after_clear_proposal);
                })
            })
            .await
        }
    }

    mod clear_pending_commit {
        use super::*;

        #[apply(all_cred_cipher)]
        #[wasm_bindgen_test]
        pub async fn should_remove_commit(case: TestCase) {
            run_test_with_client_ids(case.clone(), ["alice"], move |[alice_central]| {
                Box::pin(async move {
                    let id = conversation_id();
                    alice_central
                        .context
                        .new_conversation(&id, case.credential_type, case.cfg.clone())
                        .await
                        .unwrap();
                    assert!(alice_central.pending_commit(&id).await.is_none());

                    alice_central.context.update_keying_material(&id).await.unwrap();
                    assert!(alice_central.pending_commit(&id).await.is_some());
                    alice_central.context.clear_pending_commit(&id).await.unwrap();
                    assert!(alice_central.pending_commit(&id).await.is_none());
                })
            })
            .await
        }

        #[apply(all_cred_cipher)]
        #[wasm_bindgen_test]
        pub async fn should_fail_when_conversation_not_found(case: TestCase) {
            run_test_with_client_ids(case.clone(), ["alice"], move |[alice_central]| {
                Box::pin(async move {
                    let id = conversation_id();
                    let clear = alice_central.context.clear_pending_commit(&id).await;
                    assert!(matches!(clear.unwrap_err(), CryptoError::ConversationNotFound(conv_id) if conv_id == id))
                })
            })
            .await
        }

        #[apply(all_cred_cipher)]
        #[wasm_bindgen_test]
        pub async fn should_fail_when_pending_commit_absent(case: TestCase) {
            run_test_with_client_ids(case.clone(), ["alice"], move |[alice_central]| {
                Box::pin(async move {
                    let id = conversation_id();
                    alice_central
                        .context
                        .new_conversation(&id, case.credential_type, case.cfg.clone())
                        .await
                        .unwrap();
                    assert!(alice_central.pending_commit(&id).await.is_none());
                    let clear = alice_central.context.clear_pending_commit(&id).await;
                    assert!(matches!(clear.unwrap_err(), CryptoError::PendingCommitNotFound))
                })
            })
            .await
        }

        #[apply(all_cred_cipher)]
        #[wasm_bindgen_test]
        pub async fn should_clean_associated_key_material(case: TestCase) {
            run_test_with_client_ids(case.clone(), ["alice"], move |[cc]| {
                Box::pin(async move {
                    let id = conversation_id();
                    cc.context
                        .new_conversation(&id, case.credential_type, case.cfg.clone())
                        .await
                        .unwrap();
                    assert!(cc.pending_commit(&id).await.is_none());

                    let init = cc.context.count_entities().await;

                    cc.context.update_keying_material(&id).await.unwrap();
                    assert!(cc.pending_commit(&id).await.is_some());

                    cc.context.clear_pending_commit(&id).await.unwrap();
                    assert!(cc.pending_commit(&id).await.is_none());

                    // This whole flow should be idempotent.
                    // Here we verify that we are indeed deleting the `EncryptionKeyPair` created
                    // for the Update commit
                    let after_clear_commit = cc.context.count_entities().await;
                    assert_eq!(init, after_clear_commit);
                })
            })
            .await
        }
    }
}
