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
#[derive(Debug, derive_more::Deref, derive_more::DerefMut)]
pub struct MlsConversationCanEncrypt<'a>(&'a mut MlsConversation);

impl MlsConversationCanEncrypt<'_> {
    const REASON: &'static str = "Cannot encrypt an application message when group has pending commits or proposals";

    /// see [MlsCentral::encrypt_message]
    pub async fn encrypt_message(
        &mut self,
        message: impl AsRef<[u8]>,
        backend: &MlsCryptoProvider,
    ) -> CryptoResult<Vec<u8>> {
        self.group
            .create_message(backend, message.as_ref())
            .await
            .map_err(MlsError::from)
            .and_then(|m| m.to_bytes().map_err(MlsError::from))
            .map_err(CryptoError::from)
    }
}

impl<'a> TryFrom<&'a mut MlsConversation> for MlsConversationCanEncrypt<'a> {
    type Error = CryptoError;

    fn try_from(conv: &'a mut MlsConversation) -> CryptoResult<Self> {
        if conv.group.pending_proposals().count() == 0 && conv.group.pending_commit().is_none() {
            Ok(Self(conv))
        } else {
            Err(CryptoError::GroupStateError(Self::REASON))
        }
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
        Self::get_conversation_mut::<MlsConversationCanEncrypt>(&mut self.mls_groups, conversation)?
            .encrypt_message(message, &self.mls_backend)
            .await
    }
}

#[cfg(test)]
impl MlsConversation {
    pub fn as_can_encrypt(&mut self) -> MlsConversationCanEncrypt {
        MlsConversationCanEncrypt::try_from(self).unwrap()
    }
}

#[cfg(test)]
pub mod tests {
    use wasm_bindgen_test::*;

    use crate::{credential::CredentialSupplier, test_fixture_utils::*, test_utils::*, MlsCentral};

    use super::super::state_tests_utils::*;
    use super::*;

    wasm_bindgen_test_configure!(run_in_browser);

    pub mod state {
        use super::*;

        #[apply(all_credential_types)]
        #[wasm_bindgen_test]
        pub async fn can_send_message_when_no_pending(credential: CredentialSupplier) {
            run_test_with_central(credential, move |[mut central]| {
                Box::pin(async move {
                    let id = b"id".to_vec();
                    conv_no_pending(&mut central, &id).await;
                    let can_encrypt =
                        MlsCentral::get_conversation_mut::<MlsConversationCanEncrypt>(&mut central.mls_groups, &id);
                    assert!(can_encrypt.is_ok());
                })
            })
            .await
        }

        #[apply(all_credential_types)]
        #[wasm_bindgen_test]
        pub async fn cannot_send_message_when_pending_proposals_and_no_pending_commit(credential: CredentialSupplier) {
            run_test_with_central(credential, move |[mut central]| {
                Box::pin(async move {
                    let id = b"id".to_vec();
                    conv_pending_proposal_and_no_pending_commit(&mut central, &id).await;
                    let can_encrypt =
                        MlsCentral::get_conversation_mut::<MlsConversationCanEncrypt>(&mut central.mls_groups, &id);
                    assert!(matches!(
                        can_encrypt.unwrap_err(),
                        CryptoError::GroupStateError(MlsConversationCanEncrypt::REASON)
                    ));
                })
            })
            .await
        }

        #[apply(all_credential_types)]
        #[wasm_bindgen_test]
        pub async fn cannot_send_message_when_no_pending_proposals_and_pending_commit(credential: CredentialSupplier) {
            run_test_with_central(credential, move |[mut central]| {
                Box::pin(async move {
                    let id = b"id".to_vec();
                    conv_no_pending_proposal_and_pending_commit(&mut central, &id).await;
                    let can_encrypt =
                        MlsCentral::get_conversation_mut::<MlsConversationCanEncrypt>(&mut central.mls_groups, &id);
                    assert!(matches!(
                        can_encrypt.unwrap_err(),
                        CryptoError::GroupStateError(MlsConversationCanEncrypt::REASON)
                    ));
                })
            })
            .await
        }

        #[apply(all_credential_types)]
        #[wasm_bindgen_test]
        pub async fn cannot_send_message_when_pending_proposals_and_pending_commit(credential: CredentialSupplier) {
            run_test_with_client_ids(credential, ["alice", "bob"], move |[mut alice_central, bob_central]| {
                Box::pin(async move {
                    let id = b"id".to_vec();
                    conv_pending_proposal_and_pending_commit(&mut alice_central, bob_central, &id).await;
                    let can_encrypt = MlsCentral::get_conversation_mut::<MlsConversationCanEncrypt>(
                        &mut alice_central.mls_groups,
                        &id,
                    );
                    assert!(matches!(
                        can_encrypt.unwrap_err(),
                        CryptoError::GroupStateError(MlsConversationCanEncrypt::REASON)
                    ));
                })
            })
            .await
        }
    }
}
