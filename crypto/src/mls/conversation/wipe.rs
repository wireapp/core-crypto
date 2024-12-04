use super::{Error, Result};
use crate::context::CentralContext;
use crate::prelude::{ConversationId, MlsConversation};
use core_crypto_keystore::CryptoKeystoreMls;
use mls_crypto_provider::MlsCryptoProvider;
use openmls_traits::OpenMlsCryptoProvider;

impl CentralContext {
    /// Destroys a group locally
    ///
    /// # Errors
    /// KeyStore errors, such as IO
    #[cfg_attr(test, crate::dispotent)]
    pub async fn wipe_conversation(&self, id: &ConversationId) -> Result<()> {
        let provider = self.mls_provider().await.map_err(Error::root("getting mls provider"))?;
        self.get_conversation(id)
            .await?
            .write()
            .await
            .wipe_associated_entities(&provider)
            .await?;
        provider
            .key_store()
            .mls_group_delete(id)
            .await
            .map_err(Error::keystore("deleting mls group"))?;
        let _ = self
            .mls_groups()
            .await
            .map_err(Error::root("getting mls groups"))?
            .remove(id);
        Ok(())
    }
}

impl MlsConversation {
    async fn wipe_associated_entities(&mut self, backend: &MlsCryptoProvider) -> Result<()> {
        // the own client may or may not have generated an epoch keypair in the previous epoch
        // Since it is a terminal operation, ignoring the error is fine here.
        let _ = self.group.delete_previous_epoch_keypairs(backend).await;

        let pending_proposals = self.group.pending_proposals().cloned().collect::<Vec<_>>();
        for proposal in pending_proposals {
            // Update proposals rekey the own leaf node. Hence the associated encryption keypair has to be cleared
            self.group
                .remove_pending_proposal(backend.key_store(), proposal.proposal_reference())
                .await
                .map_err(Error::mls_operation("removing pending proposal"))?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use wasm_bindgen_test::*;

    use super::super::error::Error;
    use crate::test_utils::*;

    wasm_bindgen_test_configure!(run_in_browser);

    #[apply(all_cred_cipher)]
    #[wasm_bindgen_test]
    async fn can_wipe_group(case: TestCase) {
        run_test_with_central(case.clone(), move |[central]| {
            Box::pin(async move {
                let id = conversation_id();
                central
                    .context
                    .new_conversation(&id, case.credential_type, case.cfg.clone())
                    .await
                    .unwrap();
                assert!(central.get_conversation_unchecked(&id).await.group.is_active());

                central.context.wipe_conversation(&id).await.unwrap();
                assert!(!central.context.conversation_exists(&id).await.unwrap());
            })
        })
        .await;
    }

    #[apply(all_cred_cipher)]
    #[wasm_bindgen_test]
    async fn cannot_wipe_group_non_existent(case: TestCase) {
        run_test_with_central(case.clone(), move |[central]| {
            Box::pin(async move {
                let id = conversation_id();
                let err = central.context.wipe_conversation(&id).await.unwrap_err();
                assert!(matches!(err, Error::ConversationNotFound(conv_id) if conv_id == id));
            })
        })
        .await;
    }

    // should delete anything related to this conversation
    #[apply(all_cred_cipher)]
    #[wasm_bindgen_test]
    async fn should_cascade_deletion(case: TestCase) {
        run_test_with_client_ids(case.clone(), ["alice"], move |[cc]| {
            Box::pin(async move {
                let id = conversation_id();
                cc.context
                    .new_conversation(&id, case.credential_type, case.cfg.clone())
                    .await
                    .unwrap();
                let initial_count = cc.context.count_entities().await;

                cc.context.new_update_proposal(&id).await.unwrap();
                let post_proposal_count = cc.context.count_entities().await;
                assert_eq!(
                    post_proposal_count.encryption_keypair,
                    initial_count.encryption_keypair + 1
                );

                cc.context.wipe_conversation(&id).await.unwrap();

                let final_count = cc.context.count_entities().await;
                assert_eq!(final_count.group, 0);
                assert_eq!(final_count.encryption_keypair, final_count.key_package);
                assert_eq!(final_count.epoch_encryption_keypair, 0);
            })
        })
        .await
    }
}
