use super::{Error, Result};
use crate::prelude::MlsConversation;

impl MlsConversation {
    pub(crate) async fn get_external_sender(&self) -> Result<Vec<u8>> {
        let ext_senders = self
            .group
            .group_context_extensions()
            .external_senders()
            .ok_or(Error::MissingExternalSenderExtension)?;
        let ext_sender = ext_senders.first().ok_or(Error::MissingExternalSenderExtension)?;
        let ext_sender_public_key = ext_sender.signature_key().as_slice().to_vec();
        Ok(ext_sender_public_key)
    }
}

#[cfg(test)]
mod tests {
    use wasm_bindgen_test::*;

    use crate::test_utils::*;

    wasm_bindgen_test_configure!(run_in_browser);

    #[apply(all_cred_cipher)]
    #[wasm_bindgen_test]
    pub async fn should_fetch_ext_sender(case: TestCase) {
        run_test_with_client_ids(case.clone(), ["alice"], move |[alice_central]| {
            Box::pin(async move {
                let id = conversation_id();

                // by default in test no external sender is set. Let's add one
                let mut cfg = case.cfg.clone();
                let external_sender = alice_central.rand_external_sender(&case).await;
                cfg.external_senders = vec![external_sender.clone()];

                alice_central
                    .context
                    .new_conversation(&id, case.credential_type, cfg)
                    .await
                    .unwrap();

                let alice_ext_sender = alice_central
                    .context
                    .conversation_guard(&id)
                    .await
                    .unwrap()
                    .get_external_sender()
                    .await
                    .unwrap();
                assert!(!alice_ext_sender.is_empty());
                assert_eq!(alice_ext_sender, external_sender.signature_key().as_slice().to_vec());
            })
        })
        .await
    }
}
