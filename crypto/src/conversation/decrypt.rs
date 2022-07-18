//! MLS defines 3 kind of messages: Proposal, Commits and Application messages. Since they can (should)
//! be all encrypted we need to first decrypt them before deciding what to do with them.
//!
//! This table summarizes when a MLS group can decrypt any message:
//!
//! | can decrypt ?     | 0 pend. Commit | 1 pend. Commit |
//! |-------------------|----------------|----------------|
//! | 0 pend. Proposal  | ✅              | ✅              |
//! | 1+ pend. Proposal | ✅              | ✅              |

use openmls::framing::ProcessedMessage;

use mls_crypto_provider::MlsCryptoProvider;

use crate::{ConversationId, CryptoError, CryptoResult, MlsCentral, MlsConversation, MlsError};

/// Abstraction over a MLS group capable of decrypting a MLS message
#[derive(Debug, derive_more::Deref, derive_more::DerefMut)]
pub struct MlsConversationCanDecrypt<'a>(&'a mut MlsConversation);

impl MlsConversationCanDecrypt<'_> {
    /// see [MlsCentral::decrypt_message]
    pub async fn decrypt_message(
        &mut self,
        message: impl AsRef<[u8]>,
        backend: &MlsCryptoProvider,
    ) -> CryptoResult<(Option<Vec<u8>>, bool)> {
        let msg_in = openmls::framing::MlsMessageIn::try_from_bytes(message.as_ref()).map_err(MlsError::from)?;

        let parsed_message = self.group.parse_message(msg_in, backend).map_err(MlsError::from)?;

        let message = self
            .group
            .process_unverified_message(parsed_message, None, backend)
            .await
            .map_err(MlsError::from)?;

        let (message, is_active) = match message {
            ProcessedMessage::ApplicationMessage(app_msg) => (Some(app_msg.into_bytes()), true),
            ProcessedMessage::ProposalMessage(proposal) => {
                self.group.store_pending_proposal(*proposal);
                (None, true)
            }
            ProcessedMessage::StagedCommitMessage(staged_commit) => {
                self.group.merge_staged_commit(*staged_commit).map_err(MlsError::from)?;
                (None, self.0.group.is_active())
            }
        };

        self.persist_group_when_changed(backend, false).await?;

        Ok((message, is_active))
    }
}

impl MlsCentral {
    /// Deserializes a TLS-serialized message, then deciphers it
    ///
    /// # Arguments
    /// * `conversation` - the group/conversation id
    /// * `message` - the encrypted message as a byte array
    ///
    /// # Return type
    /// This method will return None for the message in case the provided payload is
    /// a system message, such as Proposals and Commits. Otherwise it will return the message as a
    /// byte array
    ///
    /// # Errors
    /// If the conversation can't be found, an error will be returned. Other errors are originating
    /// from OpenMls and the KeyStore
    pub async fn decrypt_message(
        &mut self,
        conversation_id: &ConversationId,
        message: impl AsRef<[u8]>,
    ) -> CryptoResult<Option<Vec<u8>>> {
        let (app_msg, is_active) =
            Self::get_conversation_mut::<MlsConversationCanDecrypt>(&mut self.mls_groups, conversation_id)?
                .decrypt_message(message.as_ref(), &self.mls_backend)
                .await?;
        if !is_active {
            self.mls_groups
                .remove(conversation_id)
                .ok_or(CryptoError::ImplementationError)?;
        }
        Ok(app_msg)
    }
}

impl<'a> TryFrom<&'a mut MlsConversation> for MlsConversationCanDecrypt<'a> {
    type Error = CryptoError;

    fn try_from(conv: &'a mut MlsConversation) -> CryptoResult<Self> {
        Ok(Self(conv))
    }
}

#[cfg(test)]
impl<'a> From<MlsConversation> for MlsConversationCanDecrypt<'a> {
    fn from(conv: MlsConversation) -> Self {
        conv.try_into().unwrap()
    }
}

#[cfg(test)]
impl MlsConversation {
    pub fn as_can_decrypt(&mut self) -> MlsConversationCanDecrypt {
        MlsConversationCanDecrypt::try_from(self).unwrap()
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
        pub async fn can_receive_message_when_no_pending(credential: CredentialSupplier) {
            run_test_with_central(credential, move |[mut central]| {
                Box::pin(async move {
                    let id = b"id".to_vec();
                    conv_no_pending(&mut central, &id).await;
                    let can_decrypt =
                        MlsCentral::get_conversation_mut::<MlsConversationCanDecrypt>(&mut central.mls_groups, &id);
                    assert!(can_decrypt.is_ok());
                })
            })
            .await
        }

        #[apply(all_credential_types)]
        #[wasm_bindgen_test]
        pub async fn can_receive_message_when_pending_proposals_and_no_pending_commit(credential: CredentialSupplier) {
            run_test_with_central(credential, move |[mut central]| {
                Box::pin(async move {
                    let id = b"id".to_vec();
                    conv_pending_proposal_and_no_pending_commit(&mut central, &id).await;
                    let can_decrypt =
                        MlsCentral::get_conversation_mut::<MlsConversationCanDecrypt>(&mut central.mls_groups, &id);
                    assert!(can_decrypt.is_ok());
                })
            })
            .await
        }

        #[apply(all_credential_types)]
        #[wasm_bindgen_test]
        pub async fn can_receive_message_when_no_pending_proposals_and_pending_commit(credential: CredentialSupplier) {
            run_test_with_central(credential, move |[mut central]| {
                Box::pin(async move {
                    let id = b"id".to_vec();
                    conv_no_pending_proposal_and_pending_commit(&mut central, &id).await;
                    let can_decrypt =
                        MlsCentral::get_conversation_mut::<MlsConversationCanDecrypt>(&mut central.mls_groups, &id);
                    assert!(can_decrypt.is_ok());
                })
            })
            .await
        }

        #[apply(all_credential_types)]
        #[wasm_bindgen_test]
        pub async fn can_receive_message_when_pending_proposals_and_pending_commit(credential: CredentialSupplier) {
            run_test_with_client_ids(credential, ["alice", "bob"], move |[mut alice_central, bob_central]| {
                Box::pin(async move {
                    let id = b"id".to_vec();
                    conv_pending_proposal_and_pending_commit(&mut alice_central, bob_central, &id).await;
                    let can_decrypt = MlsCentral::get_conversation_mut::<MlsConversationCanDecrypt>(
                        &mut alice_central.mls_groups,
                        &id,
                    );
                    assert!(can_decrypt.is_ok());
                })
            })
            .await
        }
    }
}
