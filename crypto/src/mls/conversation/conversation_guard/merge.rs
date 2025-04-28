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
    prelude::MlsProposalRef,
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
    /// # Arguments
    /// * `conversation_id` - the group/conversation id
    ///
    /// # Errors
    /// When the conversation is not found or there is no pending commit
    pub(crate) async fn clear_pending_commit(&mut self) -> Result<()> {
        let keystore = self.crypto_provider().await?.keystore();
        let mut conversation = self.conversation_mut().await;
        if conversation.group.pending_commit().is_some() {
            conversation.group.clear_pending_commit();
            conversation.persist_group_when_changed(&keystore, true).await?;
            Ok(())
        } else {
            Err(Error::PendingCommitNotFound)
        }
    }
}

#[cfg(test)]
mod tests {
    use openmls::prelude::Proposal;
    use wasm_bindgen_test::*;

    use crate::test_utils::*;

    use super::*;

    wasm_bindgen_test_configure!(run_in_browser);

    mod clear_pending_proposal {
        use super::*;

        #[apply(all_cred_cipher)]
        #[wasm_bindgen_test]
        pub async fn should_remove_proposal(case: TestContext) {
            run_test_with_client_ids(
                case.clone(),
                ["alice", "bob", "charlie"],
                move |[mut alice_central, bob_central, charlie_central]| {
                    Box::pin(async move {
                        let id = conversation_id();
                        alice_central
                            .transaction
                            .new_conversation(&id, case.credential_type, case.cfg.clone())
                            .await
                            .unwrap();
                        alice_central.invite_all(&case, &id, [&bob_central]).await.unwrap();
                        assert!(alice_central.pending_proposals(&id).await.is_empty());

                        let charlie_kp = charlie_central.get_one_key_package(&case).await;
                        let add_ref = alice_central
                            .transaction
                            .new_add_proposal(&id, charlie_kp)
                            .await
                            .unwrap()
                            .proposal_ref;

                        let remove_ref = alice_central
                            .transaction
                            .new_remove_proposal(&id, bob_central.get_client_id().await)
                            .await
                            .unwrap()
                            .proposal_ref;

                        let update_ref = alice_central
                            .transaction
                            .new_update_proposal(&id)
                            .await
                            .unwrap()
                            .proposal_ref;

                        assert_eq!(alice_central.pending_proposals(&id).await.len(), 3);
                        alice_central
                            .transaction
                            .conversation(&id)
                            .await
                            .unwrap()
                            .clear_pending_proposal(add_ref)
                            .await
                            .unwrap();
                        assert_eq!(alice_central.pending_proposals(&id).await.len(), 2);
                        assert!(
                            !alice_central
                                .pending_proposals(&id)
                                .await
                                .into_iter()
                                .any(|p| matches!(p.proposal(), Proposal::Add(_)))
                        );

                        alice_central
                            .transaction
                            .conversation(&id)
                            .await
                            .unwrap()
                            .clear_pending_proposal(remove_ref)
                            .await
                            .unwrap();
                        assert_eq!(alice_central.pending_proposals(&id).await.len(), 1);
                        assert!(
                            !alice_central
                                .pending_proposals(&id)
                                .await
                                .into_iter()
                                .any(|p| matches!(p.proposal(), Proposal::Remove(_)))
                        );

                        alice_central
                            .transaction
                            .conversation(&id)
                            .await
                            .unwrap()
                            .clear_pending_proposal(update_ref)
                            .await
                            .unwrap();
                        assert!(alice_central.pending_proposals(&id).await.is_empty());
                        assert!(
                            !alice_central
                                .pending_proposals(&id)
                                .await
                                .into_iter()
                                .any(|p| matches!(p.proposal(), Proposal::Update(_)))
                        );
                    })
                },
            )
            .await
        }

        #[apply(all_cred_cipher)]
        #[wasm_bindgen_test]
        pub async fn should_fail_when_proposal_ref_not_found(case: TestContext) {
            run_test_with_client_ids(case.clone(), ["alice"], move |[mut alice_central]| {
                Box::pin(async move {
                    let id = conversation_id();
                    alice_central
                        .transaction
                        .new_conversation(&id, case.credential_type, case.cfg.clone())
                        .await
                        .unwrap();
                    assert!(alice_central.pending_proposals(&id).await.is_empty());
                    let any_ref = MlsProposalRef::from(vec![0; case.ciphersuite().hash_length()]);
                    let clear = alice_central
                        .transaction
                        .conversation(&id)
                        .await
                        .unwrap()
                        .clear_pending_proposal(any_ref.clone())
                        .await;
                    assert!(
                        matches!(clear.unwrap_err(), Error::PendingProposalNotFound(prop_ref) if prop_ref == any_ref)
                    )
                })
            })
            .await
        }

        #[apply(all_cred_cipher)]
        #[wasm_bindgen_test]
        pub async fn should_clean_associated_key_material(case: TestContext) {
            run_test_with_client_ids(case.clone(), ["alice"], move |[mut cc]| {
                Box::pin(async move {
                    let id = conversation_id();
                    cc.transaction
                        .new_conversation(&id, case.credential_type, case.cfg.clone())
                        .await
                        .unwrap();
                    assert!(cc.pending_proposals(&id).await.is_empty());

                    let init = cc.transaction.count_entities().await;

                    let proposal_ref = cc.transaction.new_update_proposal(&id).await.unwrap().proposal_ref;
                    assert_eq!(cc.pending_proposals(&id).await.len(), 1);

                    cc.transaction
                        .conversation(&id)
                        .await
                        .unwrap()
                        .clear_pending_proposal(proposal_ref)
                        .await
                        .unwrap();
                    assert!(cc.pending_proposals(&id).await.is_empty());

                    // This whole flow should be idempotent.
                    // Here we verify that we are indeed deleting the `EncryptionKeyPair` created
                    // for the Update proposal
                    let after_clear_proposal = cc.transaction.count_entities().await;
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
        pub async fn should_remove_commit(case: TestContext) {
            run_test_with_client_ids(case.clone(), ["alice"], move |[alice_central]| {
                Box::pin(async move {
                    let id = conversation_id();
                    alice_central
                        .transaction
                        .new_conversation(&id, case.credential_type, case.cfg.clone())
                        .await
                        .unwrap();
                    assert!(alice_central.pending_commit(&id).await.is_none());

                    alice_central.create_unmerged_commit(&id).await;
                    assert!(alice_central.pending_commit(&id).await.is_some());
                    alice_central
                        .transaction
                        .conversation(&id)
                        .await
                        .unwrap()
                        .clear_pending_commit()
                        .await
                        .unwrap();
                    assert!(alice_central.pending_commit(&id).await.is_none());
                })
            })
            .await
        }

        #[apply(all_cred_cipher)]
        #[wasm_bindgen_test]
        pub async fn should_fail_when_pending_commit_absent(case: TestContext) {
            run_test_with_client_ids(case.clone(), ["alice"], move |[alice_central]| {
                Box::pin(async move {
                    let id = conversation_id();
                    alice_central
                        .transaction
                        .new_conversation(&id, case.credential_type, case.cfg.clone())
                        .await
                        .unwrap();
                    assert!(alice_central.pending_commit(&id).await.is_none());
                    let clear = alice_central
                        .transaction
                        .conversation(&id)
                        .await
                        .unwrap()
                        .clear_pending_commit()
                        .await;
                    assert!(matches!(clear.unwrap_err(), Error::PendingCommitNotFound))
                })
            })
            .await
        }

        #[apply(all_cred_cipher)]
        #[wasm_bindgen_test]
        pub async fn should_clean_associated_key_material(case: TestContext) {
            run_test_with_client_ids(case.clone(), ["alice"], move |[cc]| {
                Box::pin(async move {
                    let id = conversation_id();
                    cc.transaction
                        .new_conversation(&id, case.credential_type, case.cfg.clone())
                        .await
                        .unwrap();
                    assert!(cc.pending_commit(&id).await.is_none());

                    let init = cc.transaction.count_entities().await;

                    cc.create_unmerged_commit(&id).await;
                    assert!(cc.pending_commit(&id).await.is_some());

                    cc.transaction
                        .conversation(&id)
                        .await
                        .unwrap()
                        .clear_pending_commit()
                        .await
                        .unwrap();
                    assert!(cc.pending_commit(&id).await.is_none());

                    // This whole flow should be idempotent.
                    // Here we verify that we are indeed deleting the `EncryptionKeyPair` created
                    // for the Update commit
                    let after_clear_commit = cc.transaction.count_entities().await;
                    assert_eq!(init, after_clear_commit);
                })
            })
            .await
        }
    }
}
