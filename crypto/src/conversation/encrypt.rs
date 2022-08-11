//! Application messages are actual text messages user exchange. In MLS they can only be encrypted.
//!
//! This table summarizes when a MLS group can create an application message:
//!
//! | can encrypt ?     | 0 pend. Commit | 1 pend. Commit |
//! |-------------------|----------------|----------------|
//! | 0 pend. Proposal  | ✅              | ❌              |
//! | 1+ pend. Proposal | ❌              | ❌              |

use mls_crypto_provider::MlsCryptoProvider;

use crate::{ConversationId, CryptoError, CryptoResult, MlsCentral, MlsError};

use super::MlsConversation;

/// Abstraction over a MLS group capable of encrypting a MLS message
impl MlsConversation {
    /// see [MlsCentral::encrypt_message]
    /// It is durable because encrypting increments the message generation
    #[cfg_attr(test, crate::durable)]
    pub async fn encrypt_message(
        &mut self,
        message: impl AsRef<[u8]>,
        backend: &MlsCryptoProvider,
    ) -> CryptoResult<Vec<u8>> {
        let encrypted = self
            .group
            .create_message(backend, message.as_ref())
            .await
            .map_err(MlsError::from)
            .and_then(|m| m.to_bytes().map_err(MlsError::from))
            .map_err(CryptoError::from)?;
        self.persist_group_when_changed(backend, false).await?;
        Ok(encrypted)
    }
}

impl MlsCentral {
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
    pub async fn encrypt_message(
        &mut self,
        conversation: &ConversationId,
        message: impl AsRef<[u8]>,
    ) -> CryptoResult<Vec<u8>> {
        Self::get_conversation_mut(&mut self.mls_groups, conversation)?
            .encrypt_message(message, &self.mls_backend)
            .await
    }
}

#[cfg(test)]
pub mod tests {
    use wasm_bindgen_test::*;

    use crate::{credential::CredentialSupplier, test_utils::*, MlsConversationConfiguration};

    wasm_bindgen_test_configure!(run_in_browser);

    #[apply(all_credential_types)]
    #[wasm_bindgen_test]
    pub async fn can_encrypt_app_message(credential: CredentialSupplier) {
        run_test_with_client_ids(
            credential,
            ["alice", "bob"],
            move |[mut alice_central, mut bob_central]| {
                Box::pin(async move {
                    let id = conversation_id();
                    alice_central
                        .new_conversation(id.clone(), MlsConversationConfiguration::default())
                        .await
                        .unwrap();
                    alice_central.invite(&id, &mut bob_central).await.unwrap();

                    let msg = b"Hello bob";
                    let encrypted = alice_central.encrypt_message(&id, msg).await.unwrap();
                    assert_ne!(&msg[..], &encrypted[..]);
                    let decrypted = bob_central
                        .decrypt_message(&id, encrypted)
                        .await
                        .unwrap()
                        .app_msg
                        .unwrap();
                    assert_eq!(&decrypted[..], &msg[..]);
                })
            },
        )
        .await
    }

    // Ensures encrypting an application message is durable
    #[apply(all_credential_types)]
    #[wasm_bindgen_test]
    pub async fn can_encrypt_consecutive_messages(credential: CredentialSupplier) {
        run_test_with_client_ids(
            credential,
            ["alice", "bob"],
            move |[mut alice_central, mut bob_central]| {
                Box::pin(async move {
                    let id = conversation_id();
                    alice_central
                        .new_conversation(id.clone(), MlsConversationConfiguration::default())
                        .await
                        .unwrap();
                    alice_central.invite(&id, &mut bob_central).await.unwrap();

                    let msg = b"Hello bob";
                    let encrypted = alice_central.encrypt_message(&id, msg).await.unwrap();
                    assert_ne!(&msg[..], &encrypted[..]);
                    let decrypted = bob_central
                        .decrypt_message(&id, encrypted)
                        .await
                        .unwrap()
                        .app_msg
                        .unwrap();
                    assert_eq!(&decrypted[..], &msg[..]);

                    let msg = b"Hello bob again";
                    let encrypted = alice_central.encrypt_message(&id, msg).await.unwrap();
                    assert_ne!(&msg[..], &encrypted[..]);
                    let decrypted = bob_central
                        .decrypt_message(&id, encrypted)
                        .await
                        .unwrap()
                        .app_msg
                        .unwrap();
                    assert_eq!(&decrypted[..], &msg[..]);
                })
            },
        )
        .await
    }
}
