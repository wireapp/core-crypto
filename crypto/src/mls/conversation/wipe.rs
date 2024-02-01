use crate::prelude::{ConversationId, CryptoResult, MlsCentral, MlsConversation, MlsError};
use core_crypto_keystore::CryptoKeystoreMls;
use mls_crypto_provider::MlsCryptoProvider;
use openmls_traits::OpenMlsCryptoProvider;

impl MlsCentral {
    /// Destroys a group locally
    ///
    /// # Errors
    /// KeyStore errors, such as IO
    #[cfg_attr(test, crate::dispotent)]
    pub async fn wipe_conversation(&mut self, id: &ConversationId) -> CryptoResult<()> {
        self.get_conversation(id)
            .await?
            .write()
            .await
            .wipe_associated_entities(&self.mls_backend)
            .await?;
        self.mls_backend.key_store().mls_group_delete(id).await?;
        let _ = self.mls_groups.remove(id);
        Ok(())
    }
}

impl MlsConversation {
    async fn wipe_associated_entities(&mut self, backend: &MlsCryptoProvider) -> CryptoResult<()> {
        // the own client may or may not have generated an epoch keypair in the previous epoch
        // Since it is a terminal operation, ignoring the error is fine here.
        let _ = self.group.delete_previous_epoch_keypairs(backend).await;

        let pending_proposals = self.group.pending_proposals().cloned().collect::<Vec<_>>();
        for proposal in pending_proposals {
            // Update proposals rekey the own leaf node. Hence the associated encryption keypair has to be cleared
            self.group
                .remove_pending_proposal(backend.key_store(), proposal.proposal_reference())
                .await
                .map_err(MlsError::from)?;
        }

        Ok(())
    }
}

#[cfg(test)]
pub mod tests {
    use wasm_bindgen_test::*;

    use crate::{prelude::CryptoError, test_utils::*};

    wasm_bindgen_test_configure!(run_in_browser);

    #[apply(all_cred_cipher)]
    #[wasm_bindgen_test]
    pub async fn can_wipe_group(case: TestCase) {
        run_test_with_central(case.clone(), move |[mut central]| {
            Box::pin(async move {
                let id = conversation_id();
                central
                    .mls_central
                    .new_conversation(&id, case.credential_type, case.cfg.clone())
                    .await
                    .unwrap();
                assert!(central
                    .mls_central
                    .get_conversation_unchecked(&id)
                    .await
                    .group
                    .is_active());

                central.mls_central.wipe_conversation(&id).await.unwrap();
                assert!(!central.mls_central.conversation_exists(&id).await);
            })
        })
        .await;
    }

    #[apply(all_cred_cipher)]
    #[wasm_bindgen_test]
    pub async fn cannot_wipe_group_non_existent(case: TestCase) {
        run_test_with_central(case.clone(), move |[mut central]| {
            Box::pin(async move {
                let id = conversation_id();
                let err = central.mls_central.wipe_conversation(&id).await.unwrap_err();
                assert!(matches!(err, CryptoError::ConversationNotFound(conv_id) if conv_id == id));
            })
        })
        .await;
    }

    // should delete anything related to this conversation
    #[apply(all_cred_cipher)]
    #[wasm_bindgen_test]
    pub async fn should_cascade_deletion(case: TestCase) {
        run_test_with_client_ids(case.clone(), ["alice"], move |[mut cc]| {
            Box::pin(async move {
                let id = conversation_id();
                cc.mls_central
                    .new_conversation(&id, case.credential_type, case.cfg.clone())
                    .await
                    .unwrap();
                let initial_count = cc.mls_central.count_entities().await;

                cc.mls_central.new_update_proposal(&id).await.unwrap();
                let post_proposal_count = cc.mls_central.count_entities().await;
                assert_eq!(
                    post_proposal_count.encryption_keypair,
                    initial_count.encryption_keypair + 1
                );

                cc.mls_central.wipe_conversation(&id).await.unwrap();

                let final_count = cc.mls_central.count_entities().await;
                assert_eq!(final_count.group, 0);
                assert_eq!(final_count.encryption_keypair, final_count.key_package);
                assert_eq!(final_count.epoch_encryption_keypair, 0);
            })
        })
        .await
    }
}
