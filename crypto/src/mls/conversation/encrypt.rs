//! Application messages are actual text messages user exchange. In MLS they can only be encrypted.
//!
//! This table summarizes when a MLS group can create an application message:
//!
//! | can encrypt ?     | 0 pend. Commit | 1 pend. Commit |
//! |-------------------|----------------|----------------|
//! | 0 pend. Proposal  | ✅              | ❌              |
//! | 1+ pend. Proposal | ❌              | ❌              |

use mls_crypto_provider::TransactionalCryptoProvider;
use openmls::prelude::MlsMessageOutBody;

use crate::{mls::context::CentralContext, prelude::Client};
use crate::{mls::ConversationId, CryptoError, CryptoResult, MlsError};

use super::MlsConversation;

/// Abstraction over a MLS group capable of encrypting a MLS message
impl MlsConversation {
    /// see [MlsCentral::encrypt_message]
    /// It is durable because encrypting increments the message generation
    #[cfg_attr(test, crate::durable)]
    pub async fn encrypt_message(
        &mut self,
        client: &Client,
        message: impl AsRef<[u8]>,
        backend: &TransactionalCryptoProvider,
    ) -> CryptoResult<Vec<u8>> {
        let signer = &self
            .find_current_credential_bundle(client)?
            .ok_or(CryptoError::IdentityInitializationError)?
            .signature_key;
        let encrypted = self
            .group
            .create_message(backend, signer, message.as_ref())
            .map_err(MlsError::from)?;

        // make sure all application messages are encrypted
        debug_assert!(matches!(encrypted.body, MlsMessageOutBody::PrivateMessage(_)));

        let encrypted = encrypted.to_bytes().map_err(MlsError::from)?;

        self.persist_group_when_changed(&backend.transaction(), false).await?;
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
    pub async fn encrypt_message(
        &self,
        conversation: &ConversationId,
        message: impl AsRef<[u8]>,
    ) -> CryptoResult<Vec<u8>> {
        let client_guard = self.mls_client().await?;
        let client = client_guard.as_ref().ok_or(CryptoError::MlsNotInitialized)?;
        self.get_conversation(conversation)
            .await?
            .write()
            .await
            .encrypt_message(client, message, &self.mls_provider().await?)
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
        run_test_with_client_ids(
            case.clone(),
            ["alice", "bob"],
            move |[mut alice_central, mut bob_central]| {
                Box::pin(async move {
                    let id = conversation_id();
                    alice_central
                        .mls_central
                        .new_conversation(&id, case.credential_type, case.cfg.clone())
                        .await
                        .unwrap();
                    alice_central
                        .mls_central
                        .invite_all(&case, &id, [&mut bob_central.mls_central])
                        .await
                        .unwrap();

                    let msg = b"Hello bob";
                    let encrypted = alice_central.mls_central.encrypt_message(&id, msg).await.unwrap();
                    assert_ne!(&msg[..], &encrypted[..]);
                    let decrypted = bob_central
                        .mls_central
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
    #[apply(all_cred_cipher)]
    #[wasm_bindgen_test]
    async fn can_encrypt_consecutive_messages(case: TestCase) {
        run_test_with_client_ids(
            case.clone(),
            ["alice", "bob"],
            move |[mut alice_central, mut bob_central]| {
                Box::pin(async move {
                    let id = conversation_id();
                    alice_central
                        .mls_central
                        .new_conversation(&id, case.credential_type, case.cfg.clone())
                        .await
                        .unwrap();
                    alice_central
                        .mls_central
                        .invite_all(&case, &id, [&mut bob_central.mls_central])
                        .await
                        .unwrap();

                    let msg = b"Hello bob";
                    let encrypted = alice_central.mls_central.encrypt_message(&id, msg).await.unwrap();
                    assert_ne!(&msg[..], &encrypted[..]);
                    let decrypted = bob_central
                        .mls_central
                        .decrypt_message(&id, encrypted)
                        .await
                        .unwrap()
                        .app_msg
                        .unwrap();
                    assert_eq!(&decrypted[..], &msg[..]);

                    let msg = b"Hello bob again";
                    let encrypted = alice_central.mls_central.encrypt_message(&id, msg).await.unwrap();
                    assert_ne!(&msg[..], &encrypted[..]);
                    let decrypted = bob_central
                        .mls_central
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
