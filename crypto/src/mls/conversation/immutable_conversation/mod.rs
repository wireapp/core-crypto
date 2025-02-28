use super::{ConversationWithCentral, MlsConversation, Result};
use crate::prelude::MlsCentral;

/// An ImmutableConversation wraps a `MlsConversation`.
///
/// It only exposes the read-only interface of the conversation.
pub struct ImmutableConversation {
    inner: MlsConversation,
    central: MlsCentral,
}

#[cfg_attr(target_family = "wasm", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_family = "wasm"), async_trait::async_trait)]
impl<'inner> ConversationWithCentral<'inner> for ImmutableConversation {
    type Central = MlsCentral;

    type Conversation = &'inner MlsConversation;

    async fn central(&self) -> Result<MlsCentral> {
        Ok(self.central.clone())
    }

    async fn conversation(&'inner self) -> &'inner MlsConversation {
        &self.inner
    }
}

impl ImmutableConversation {
    pub(crate) fn new(inner: MlsConversation, central: MlsCentral) -> Self {
        Self { inner, central }
    }

    /// Returns the epoch of a given conversation
    pub async fn epoch(&self) -> u64 {
        self.conversation().await.group.epoch().as_u64()
    }

    /// Returns the ciphersuite of a given conversation
    pub async fn ciphersuite(&self) -> MlsCiphersuite {
        self.conversation().await.ciphersuite()
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
        self.conversation()
            .await
            .export_secret_key(&self.mls_provider().await?, key_length)
    }

    /// Exports the clients from a conversation
    ///
    /// # Arguments
    /// * `conversation_id` - the group/conversation id
    pub async fn get_client_ids(&self) -> Vec<ClientId> {
        self.conversation().await.get_client_ids()
    }

    /// Returns the raw public key of the single external sender present in this group.
    /// This should be used to initialize a subconversation
    pub async fn get_external_sender(&self) -> Result<Vec<u8>> {
        self.conversation().await.get_external_sender().await
    }
}
