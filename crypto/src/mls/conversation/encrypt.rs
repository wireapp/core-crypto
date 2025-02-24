//! Application messages are actual text messages user exchange. In MLS they can only be encrypted.
//!
//! This table summarizes when a MLS group can create an application message:
//!
//! | can encrypt ?     | 0 pend. Commit | 1 pend. Commit |
//! |-------------------|----------------|----------------|
//! | 0 pend. Proposal  | ✅              | ❌              |
//! | 1+ pend. Proposal | ❌              | ❌              |

use mls_crypto_provider::MlsCryptoProvider;
use openmls::prelude::MlsMessageOutBody;

use super::{Error, Result};
use crate::{
    context::CentralContext,
    mls::{ConversationId, MlsConversation},
    prelude::Client,
    MlsError, RecursiveError,
};

/// Abstraction over a MLS group capable of encrypting a MLS message
impl MlsConversation {
    /// see [CentralContext::encrypt_message]
    /// It is durable because encrypting increments the message generation
    #[cfg_attr(test, crate::durable)]
    pub async fn encrypt_message(
        &mut self,
        client: &Client,
        message: impl AsRef<[u8]>,
        backend: &MlsCryptoProvider,
    ) -> Result<Vec<u8>> {
        let signer = &self
            .find_current_credential_bundle(client)
            .await
            .map_err(|_| Error::IdentityInitializationError)?
            .signature_key;
        let encrypted = self
            .group
            .create_message(backend, signer, message.as_ref())
            .map_err(MlsError::wrap("creating message"))?;

        // make sure all application messages are encrypted
        debug_assert!(matches!(encrypted.body, MlsMessageOutBody::PrivateMessage(_)));

        let encrypted = encrypted
            .to_bytes()
            .map_err(MlsError::wrap("constructing byte vector of encrypted message"))?;

        self.persist_group_when_changed(&backend.keystore(), false).await?;
        Ok(encrypted)
    }
}

impl CentralContext {
    /// Encrypts a raw payload then serializes it to the TLS wire format
    ///
    /// # Arguments
    /// * `conversation` - the group/conversation id
    /// * `message` - the message as a byte array
    ///
    /// # Return type
    /// This method will return an encrypted TLS serialized message.
    ///
    /// # Errors
    /// If the conversation can't be found, an error will be returned. Other errors are originating
    /// from OpenMls and the KeyStore
    #[cfg_attr(test, crate::idempotent)]
    pub async fn encrypt_message(&self, conversation: &ConversationId, message: impl AsRef<[u8]>) -> Result<Vec<u8>> {
        let client = self
            .mls_client()
            .await
            .map_err(RecursiveError::root("getting mls client"))?;
        self.get_conversation(conversation)
            .await?
            .write()
            .await
            .encrypt_message(
                &client,
                message,
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

    wasm_bindgen_test_configure!(run_in_browser);

    #[apply(all_cred_cipher)]
    #[wasm_bindgen_test]
    async fn can_encrypt_app_message(case: TestCase) {
        run_test_with_client_ids(case.clone(), ["alice", "bob"], move |[alice_central, bob_central]| {
            Box::pin(async move {
                let id = conversation_id();
                alice_central
                    .context
                    .new_conversation(&id, case.credential_type, case.cfg.clone())
                    .await
                    .unwrap();
                alice_central.invite_all(&case, &id, [&bob_central]).await.unwrap();

                let msg = b"Hello bob";
                let encrypted = alice_central
                    .context
                    .conversation_guard(&id)
                    .await
                    .unwrap()
                    .encrypt_message(msg)
                    .await
                    .unwrap();
                assert_ne!(&msg[..], &encrypted[..]);
                let decrypted = bob_central
                    .context
                    .decrypt_message(&id, encrypted)
                    .await
                    .unwrap()
                    .app_msg
                    .unwrap();
                assert_eq!(&decrypted[..], &msg[..]);
            })
        })
        .await
    }

    // Ensures encrypting an application message is durable
    #[apply(all_cred_cipher)]
    #[wasm_bindgen_test]
    async fn can_encrypt_consecutive_messages(case: TestCase) {
        run_test_with_client_ids(case.clone(), ["alice", "bob"], move |[alice_central, bob_central]| {
            Box::pin(async move {
                let id = conversation_id();
                alice_central
                    .context
                    .new_conversation(&id, case.credential_type, case.cfg.clone())
                    .await
                    .unwrap();
                alice_central.invite_all(&case, &id, [&bob_central]).await.unwrap();

                let msg = b"Hello bob";
                let encrypted = alice_central
                    .context
                    .conversation_guard(&id)
                    .await
                    .unwrap()
                    .encrypt_message(msg)
                    .await
                    .unwrap();
                assert_ne!(&msg[..], &encrypted[..]);
                let decrypted = bob_central
                    .context
                    .decrypt_message(&id, encrypted)
                    .await
                    .unwrap()
                    .app_msg
                    .unwrap();
                assert_eq!(&decrypted[..], &msg[..]);

                let msg = b"Hello bob again";
                let encrypted = alice_central
                    .context
                    .conversation_guard(&id)
                    .await
                    .unwrap()
                    .encrypt_message(msg)
                    .await
                    .unwrap();
                assert_ne!(&msg[..], &encrypted[..]);
                let decrypted = bob_central
                    .context
                    .decrypt_message(&id, encrypted)
                    .await
                    .unwrap()
                    .app_msg
                    .unwrap();
                assert_eq!(&decrypted[..], &msg[..]);
            })
        })
        .await
    }
}
