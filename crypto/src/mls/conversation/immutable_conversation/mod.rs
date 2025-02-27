mod e2e_identity;

use super::{Error, MlsConversation, Result};
use crate::prelude::{ClientId, MlsCiphersuite};
use mls_crypto_provider::MlsCryptoProvider;

/// A ImmutableConversation wraps a `MlsConversation`.
///
/// It only exposes the read-only interface of the conversation.
pub struct ImmutableConversation {
    inner: MlsConversation,
    mls_provider: MlsCryptoProvider,
}

impl ImmutableConversation {
    pub(crate) fn new(inner: MlsConversation, mls_provider: MlsCryptoProvider) -> Self {
        Self { inner, mls_provider }
    }

    fn conversation(&self) -> &MlsConversation {
        &self.inner
    }

    fn mls_provider(&self) -> &MlsCryptoProvider {
        &self.mls_provider
    }

    /// Returns the epoch of a given conversation
    pub fn epoch(&self) -> u64 {
        self.conversation().group.epoch().as_u64()
    }

    /// Returns the ciphersuite of a given conversation
    pub fn ciphersuite(&self) -> MlsCiphersuite {
        self.conversation().ciphersuite()
    }

    /// Derives a new key from the one in the group, to be used elsewhere.
    ///
    /// # Arguments
    /// * `key_length` - the length of the key to be derived. If the value is higher than the
    ///     bounds of `u16` or the context hash * 255, an error will be returned
    ///
    /// # Errors
    /// OpenMls secret generation error
    pub async fn export_secret_key(&self, key_length: usize) -> Result<Vec<u8>> {
        self.conversation().export_secret_key(self.mls_provider(), key_length)
    }

    /// Exports the clients from a conversation
    ///
    /// # Arguments
    /// * `conversation_id` - the group/conversation id
    ///
    /// # Errors
    /// if the conversation can't be found
    pub async fn get_client_ids(&self) -> Vec<ClientId> {
        self.conversation().get_client_ids()
    }

    /// Returns the raw public key of the single external sender present in this group.
    /// This should be used to initialize a subconversation
    pub async fn get_external_sender(&self) -> Result<Vec<u8>> {
        self.conversation().get_external_sender().await
    }
}
