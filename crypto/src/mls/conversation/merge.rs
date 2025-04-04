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

use super::Result;
use crate::{MlsError, mls::MlsConversation, prelude::Session};

/// Abstraction over a MLS group capable of merging a commit
impl MlsConversation {
    /// see [TransactionContext::commit_accepted]
    #[cfg_attr(test, crate::durable)]
    pub(crate) async fn commit_accepted(&mut self, client: &Session, backend: &MlsCryptoProvider) -> Result<()> {
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

        client
            .notify_epoch_changed(self.id.clone(), self.group.epoch().as_u64())
            .await;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use wasm_bindgen_test::*;

    use crate::test_utils::*;

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
                        .conversation(&id)
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
            use crate::mls::HasClientAndProvider as _;

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
                        .commit_accepted(
                            &alice_central.context.client().await.unwrap(),
                            &alice_central.client.mls_backend,
                        )
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
                        .conversation(&id)
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
}
