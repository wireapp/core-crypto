use crate::{
    prelude::{ConversationId, MlsCentral, MlsConversation},
    prelude::{CryptoError, CryptoResult},
};

impl MlsCentral {
    /// Returns the raw public key of the single external sender present in this group.
    /// This should be used to initialize a subconversation
    pub async fn get_external_sender(&mut self, id: &ConversationId) -> CryptoResult<Vec<u8>> {
        self.get_conversation(id)
            .await?
            .read()
            .await
            .get_external_sender()
            .await
    }
}

impl MlsConversation {
    async fn get_external_sender(&self) -> CryptoResult<Vec<u8>> {
        let ext_senders = self
            .group
            .group_context_extensions()
            .external_senders()
            .ok_or(CryptoError::MissingExternalSenderExtension)?;
        let ext_sender = ext_senders.first().ok_or(CryptoError::MissingExternalSenderExtension)?;
        let ext_sender_public_key = ext_sender.signature_key().as_slice().to_vec();
        Ok(ext_sender_public_key)
    }
}

#[cfg(test)]
pub mod tests {
    use wasm_bindgen_test::*;

    use crate::test_utils::*;

    wasm_bindgen_test_configure!(run_in_browser);

    #[apply(all_cred_cipher)]
    #[wasm_bindgen_test]
    pub async fn should_fetch_ext_sender(case: TestCase) {
        run_test_with_client_ids(case.clone(), ["alice"], move |[mut alice_central]| {
            Box::pin(async move {
                let id = conversation_id();

                // by default in test no external sender is set. Let's add one
                let mut cfg = case.cfg.clone();
                let external_sender = alice_central.mls_central.rand_external_sender(&case);
                cfg.external_senders = vec![external_sender.clone()];

                alice_central
                    .mls_central
                    .new_conversation(&id, case.credential_type, cfg)
                    .await
                    .unwrap();

                let alice_ext_sender = alice_central.mls_central.get_external_sender(&id).await.unwrap();
                assert!(!alice_ext_sender.is_empty());
                assert_eq!(alice_ext_sender, external_sender.signature_key().as_slice().to_vec());
            })
        })
        .await
    }
}
