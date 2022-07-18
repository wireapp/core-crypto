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
