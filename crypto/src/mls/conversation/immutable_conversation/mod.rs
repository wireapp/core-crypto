use super::{ConversationWithMls, MlsConversation, Result};
use crate::prelude::Client;

/// An ImmutableConversation wraps a `MlsConversation`.
///
/// It only exposes the read-only interface of the conversation.
pub struct ImmutableConversation {
    inner: MlsConversation,
    client: Client,
}

#[cfg_attr(target_family = "wasm", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_family = "wasm"), async_trait::async_trait)]
impl<'inner> ConversationWithMls<'inner> for ImmutableConversation {
    type Context = Client;

    type Conversation = &'inner MlsConversation;

    async fn context(&self) -> Result<Client> {
        Ok(self.client.clone())
    }

    async fn conversation(&'inner self) -> &'inner MlsConversation {
        &self.inner
    }
}

impl ImmutableConversation {
    pub(crate) fn new(inner: MlsConversation, client: Client) -> Self {
        Self { inner, client }
    }
}
