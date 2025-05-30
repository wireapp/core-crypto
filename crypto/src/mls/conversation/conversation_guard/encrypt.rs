//! The methods in this module are concerned with message encryption.

use super::ConversationGuard;
use super::Result;
use crate::MlsError;
use crate::mls::conversation::ConversationWithMls as _;
use openmls::prelude::MlsMessageOutBody;

impl ConversationGuard {
    /// Encrypts a raw payload then serializes it to the TLS wire format
    /// Can only be called when there is no pending commit and no pending proposal.
    ///
    /// # Arguments
    /// * `message` - the message as a byte array
    ///
    /// # Return type
    /// This method will return an encrypted TLS serialized message.
    ///
    /// # Errors
    /// If the conversation can't be found, an error will be returned. Other errors are originating
    /// from OpenMls and the KeyStore
    pub async fn encrypt_message(&mut self, message: impl AsRef<[u8]>) -> Result<Vec<u8>> {
        let backend = self.crypto_provider().await?;
        let credential = self.credential_bundle().await?;
        let signer = credential.signature_key();
        let mut inner = self.conversation_mut().await;
        let encrypted = inner
            .group
            .create_message(&backend, signer, message.as_ref())
            .map_err(MlsError::wrap("creating message"))?;

        // make sure all application messages are encrypted
        debug_assert!(matches!(encrypted.body, MlsMessageOutBody::PrivateMessage(_)));

        let encrypted = encrypted
            .to_bytes()
            .map_err(MlsError::wrap("constructing byte vector of encrypted message"))?;

        inner.persist_group_when_changed(&backend.keystore(), false).await?;
        Ok(encrypted)
    }
}

#[cfg(test)]
mod tests {
    use wasm_bindgen_test::*;

    use crate::test_utils::*;

    wasm_bindgen_test_configure!(run_in_browser);

    #[apply(all_cred_cipher)]
    #[wasm_bindgen_test]
    async fn can_encrypt_app_message(case: TestContext) {
        let [alice, bob] = case.sessions().await;
        Box::pin(async move {
            let conversation = case.create_conversation([&alice, &bob]).await;

            let msg = b"Hello bob";
            let encrypted = conversation.guard().await.encrypt_message(msg).await.unwrap();
            assert_ne!(&msg[..], &encrypted[..]);
            let decrypted = conversation
                .guard_of(&bob)
                .await
                .decrypt_message(encrypted)
                .await
                .unwrap()
                .app_msg
                .unwrap();
            assert_eq!(&decrypted[..], &msg[..]);
        })
        .await
    }

    // Ensures encrypting an application message is durable
    #[apply(all_cred_cipher)]
    #[wasm_bindgen_test]
    async fn can_encrypt_consecutive_messages(case: TestContext) {
        let [alice, bob] = case.sessions().await;
        Box::pin(async move {
            let conversation = case.create_conversation([&alice, &bob]).await;

            let msg = b"Hello bob";
            let encrypted = conversation.guard().await.encrypt_message(msg).await.unwrap();
            assert_ne!(&msg[..], &encrypted[..]);
            let decrypted = conversation
                .guard_of(&bob)
                .await
                .decrypt_message(encrypted)
                .await
                .unwrap()
                .app_msg
                .unwrap();
            assert_eq!(&decrypted[..], &msg[..]);

            let msg = b"Hello bob again";
            let encrypted = conversation.guard().await.encrypt_message(msg).await.unwrap();
            assert_ne!(&msg[..], &encrypted[..]);
            let decrypted = conversation
                .guard_of(&bob)
                .await
                .decrypt_message(encrypted)
                .await
                .unwrap()
                .app_msg
                .unwrap();
            assert_eq!(&decrypted[..], &msg[..]);
        })
        .await
    }
}
