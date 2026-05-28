//! The methods in this module are concerned with message encryption.

use openmls::prelude::MlsMessageOutBody;

use super::{ConversationMut, Result};
use crate::OpenMlsError;

impl ConversationMut {
    /// Encrypts a raw payload then serializes it to the TLS wire format.
    ///
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
        #[cfg(debug_assertions)]
        {
            let group = &self.group().await;
            debug_assert!(
                group.pending_commit().is_none(),
                "precondition failed; a pending commit exists"
            );
            debug_assert!(
                group.pending_proposals().next().is_none(),
                "precondition failed; a pending proposal exists"
            );
        }

        let backend = self.crypto_provider().await?;
        let credential = self.credential().await?;
        let signer = credential.signature_key();

        self.mutate_group(async |_, group, _| {
            let encrypted = group
                .create_message(&backend, signer, message.as_ref())
                .map_err(OpenMlsError::wrap("creating encrypted message"))?;
            // all application messages must be encrypted
            debug_assert!(matches!(encrypted.body, MlsMessageOutBody::PrivateMessage(_)));
            encrypted
                .to_bytes()
                .map_err(OpenMlsError::wrap("constructing byte vector of encrypted message"))
                .map_err(Into::into)
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use crate::test_utils::*;

    #[apply(all_cred_cipher)]
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
