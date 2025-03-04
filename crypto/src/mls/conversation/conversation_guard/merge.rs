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
        let keystore = self.mls_provider().await?.keystore();
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
                        alice_central.invite_all(&case, &id, [&bob_central]).await.unwrap();
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
                            .conversation_guard(&id)
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
                            .context
                            .conversation_guard(&id)
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
                            .context
                            .conversation_guard(&id)
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
        pub async fn should_fail_when_proposal_ref_not_found(case: TestCase) {
            run_test_with_client_ids(case.clone(), ["alice"], move |[mut alice_central]| {
                Box::pin(async move {
                    let id = conversation_id();
                    alice_central
                        .context
                        .new_conversation(&id, case.credential_type, case.cfg.clone())
                        .await
                        .unwrap();
                    assert!(alice_central.pending_proposals(&id).await.is_empty());
                    let any_ref = MlsProposalRef::from(vec![0; case.ciphersuite().hash_length()]);
                    let clear = alice_central
                        .context
                        .conversation_guard(&id)
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

                    cc.context
                        .conversation_guard(&id)
                        .await
                        .unwrap()
                        .clear_pending_proposal(proposal_ref)
                        .await
                        .unwrap();
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
}
