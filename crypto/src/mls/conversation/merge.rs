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

use core_crypto_keystore::entities::MlsEncryptionKeyPair;
use openmls_traits::OpenMlsCryptoProvider;

use mls_crypto_provider::MlsCryptoProvider;

use super::{Error, Result};
use crate::{MlsError, context::CentralContext, mls::MlsConversation};

#[cfg(test)]
use crate::{RecursiveError, mls::ConversationId};

/// Abstraction over a MLS group capable of merging a commit
impl MlsConversation {
    /// see [CentralContext::commit_accepted]
    #[cfg_attr(test, crate::durable)]
    pub(crate) async fn commit_accepted(&mut self, backend: &MlsCryptoProvider) -> Result<()> {
        // openmls stores here all the encryption keypairs used for update proposals..
        let previous_own_leaf_nodes = self.group.own_leaf_nodes.clone();

        self.group
            .merge_pending_commit(backend)
            .await
            .map_err(MlsError::wrap("merging pending commit"))?;
        self.persist_group_when_changed(&backend.keystore(), false).await?;

        // ..so if there's any, we clear them after the commit is merged
        for oln in &previous_own_leaf_nodes {
            let ek = oln.encryption_key().as_slice();
            let _ = backend.key_store().remove::<MlsEncryptionKeyPair, _>(ek).await;
        }

        Ok(())
    }

    /// see [CentralContext::clear_pending_commit]
    #[cfg_attr(test, crate::durable)]
    pub(crate) async fn clear_pending_commit(&mut self, backend: &MlsCryptoProvider) -> Result<()> {
        if self.group.pending_commit().is_some() {
            self.group.clear_pending_commit();
            self.persist_group_when_changed(&backend.keystore(), true).await?;
            Ok(())
        } else {
            Err(Error::PendingCommitNotFound)
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
///     * 200 OK --> use [CentralContext::commit_accepted] to merge the commit
///     * 409 CONFLICT --> do nothing. [CentralContext::decrypt_message] will restore the proposals not committed
///     * 5xx --> retry
impl CentralContext {
    /// Allows to remove a pending commit. Use this when backend rejects the commit
    /// you just sent e.g. if permissions have changed meanwhile.
    ///
    /// **CAUTION**: only use this when you had an explicit response from the Delivery Service
    /// e.g. 403. Do not use otherwise e.g. 5xx responses, timeout etc..
    /// **DO NOT** use when Delivery Service responds 409, pending state will be renewed
    /// in [CentralContext::decrypt_message]
    ///
    /// # Arguments
    /// * `conversation_id` - the group/conversation id
    ///
    /// # Errors
    /// When the conversation is not found or there is no pending commit
    #[cfg(test)]
    #[cfg_attr(test, crate::idempotent)]
    pub(crate) async fn clear_pending_commit(&self, conversation_id: &ConversationId) -> Result<()> {
        self.get_conversation(conversation_id)
            .await?
            .write()
            .await
            .clear_pending_commit(
                &self
                    .mls_provider()
                    .await
                    .map_err(RecursiveError::root("getting mls provider"))?,
            )
            .await
    }
}

#[cfg(test)]
mod tests {
    use wasm_bindgen_test::*;

    use crate::test_utils::*;

    use super::*;

    wasm_bindgen_test_configure!(run_in_browser);

    mod commit_accepted {
        use super::*;

        #[apply(all_cred_cipher)]
        #[wasm_bindgen_test]
        async fn should_apply_pending_commit(case: TestCase) {
            run_test_with_client_ids(case.clone(), ["alice", "bob"], move |[alice_central, bob_central]| {
                Box::pin(async move {
                    let id = conversation_id();
                    alice_central
                        .context
                        .new_conversation(&id, case.credential_type, case.cfg.clone())
                        .await
                        .unwrap();
                    alice_central.invite_all(&case, &id, [&bob_central]).await.unwrap();
                    assert_eq!(alice_central.get_conversation_unchecked(&id).await.members().len(), 2);
                    alice_central
                        .context
                        .conversation_guard(&id)
                        .await
                        .unwrap()
                        .remove_members(&[bob_central.get_client_id().await])
                        .await
                        .unwrap();
                    assert_eq!(alice_central.get_conversation_unchecked(&id).await.members().len(), 1);
                })
            })
            .await
        }

        #[apply(all_cred_cipher)]
        #[wasm_bindgen_test]
        async fn should_clear_pending_commit_and_proposals(case: TestCase) {
            run_test_with_client_ids(case.clone(), ["alice"], move |[mut alice_central]| {
                Box::pin(async move {
                    let id = conversation_id();
                    alice_central
                        .context
                        .new_conversation(&id, case.credential_type, case.cfg.clone())
                        .await
                        .unwrap();
                    alice_central.context.new_update_proposal(&id).await.unwrap();
                    alice_central.create_unmerged_commit(&id).await;
                    assert!(!alice_central.pending_proposals(&id).await.is_empty());
                    assert!(alice_central.pending_commit(&id).await.is_some());
                    alice_central
                        .get_conversation_unchecked(&id)
                        .await
                        .commit_accepted(&alice_central.central.mls_backend)
                        .await
                        .unwrap();
                    assert!(alice_central.pending_commit(&id).await.is_none());
                    assert!(alice_central.pending_proposals(&id).await.is_empty());
                })
            })
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

                    alice_central
                        .context
                        .conversation_guard(&id)
                        .await
                        .unwrap()
                        .commit_pending_proposals()
                        .await
                        .unwrap();

                    let final_count = alice_central.context.count_entities().await;
                    assert_eq!(initial_count, final_count);
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

                    alice_central.create_unmerged_commit(&id).await;
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
            use crate::LeafError;

            run_test_with_client_ids(case.clone(), ["alice"], move |[alice_central]| {
                Box::pin(async move {
                    let id = conversation_id();
                    let clear = alice_central.context.clear_pending_commit(&id).await;
                    assert!(matches!(clear.unwrap_err(), Error::Leaf(LeafError::ConversationNotFound(conv_id)) if conv_id == id))
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
                    assert!(matches!(clear.unwrap_err(), Error::PendingCommitNotFound))
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

                    cc.create_unmerged_commit(&id).await;
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
