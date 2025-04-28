use super::Result;
use crate::{MlsError, prelude::MlsConversation};
use mls_crypto_provider::MlsCryptoProvider;
use openmls_traits::OpenMlsCryptoProvider;

impl MlsConversation {
    pub(crate) async fn wipe_associated_entities(&mut self, backend: &MlsCryptoProvider) -> Result<()> {
        // the own client may or may not have generated an epoch keypair in the previous epoch
        // Since it is a terminal operation, ignoring the error is fine here.
        let _ = self.group.delete_previous_epoch_keypairs(backend).await;

        let pending_proposals = self.group.pending_proposals().cloned().collect::<Vec<_>>();
        for proposal in pending_proposals {
            // Update proposals rekey the own leaf node. Hence the associated encryption keypair has to be cleared
            self.group
                .remove_pending_proposal(backend.key_store(), proposal.proposal_reference())
                .await
                .map_err(MlsError::wrap("removing pending proposal"))?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::test_utils::*;
    use wasm_bindgen_test::*;

    wasm_bindgen_test_configure!(run_in_browser);

    // should delete anything related to this conversation
    #[apply(all_cred_cipher)]
    #[wasm_bindgen_test]
    async fn should_cascade_deletion(case: TestContext) {
        run_test_with_client_ids(case.clone(), ["alice"], move |[cc]| {
            Box::pin(async move {
                let id = conversation_id();
                cc.transaction
                    .new_conversation(&id, case.credential_type, case.cfg.clone())
                    .await
                    .unwrap();
                assert!(cc.get_conversation_unchecked(&id).await.group.is_active());
                let initial_count = cc.transaction.count_entities().await;

                cc.transaction.new_update_proposal(&id).await.unwrap();
                let post_proposal_count = cc.transaction.count_entities().await;
                assert_eq!(
                    post_proposal_count.encryption_keypair,
                    initial_count.encryption_keypair + 1
                );

                cc.transaction.conversation(&id).await.unwrap().wipe().await.unwrap();

                let final_count = cc.transaction.count_entities().await;
                assert!(!cc.transaction.conversation_exists(&id).await.unwrap());
                assert_eq!(final_count.group, 0);
                assert_eq!(final_count.encryption_keypair, final_count.key_package);
                assert_eq!(final_count.epoch_encryption_keypair, 0);
            })
        })
        .await
    }
}
