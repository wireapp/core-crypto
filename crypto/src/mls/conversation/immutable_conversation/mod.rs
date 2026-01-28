use core_crypto_keystore::Database;

use super::{ConversationWithMls, MlsConversation, Result};
use crate::Session;

/// An ImmutableConversation wraps a `MlsConversation`.
///
/// It only exposes the read-only interface of the conversation.
pub struct ImmutableConversation<D> {
    inner: MlsConversation,
    client: Session<D>,
}

#[cfg_attr(target_family = "wasm", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_family = "wasm"), async_trait::async_trait)]
impl<'inner> ConversationWithMls<'inner> for ImmutableConversation<Database> {
    type Context = Session<Database>;

    type Conversation = &'inner MlsConversation;

    async fn context(&self) -> Result<Session<Database>> {
        Ok(self.client.clone())
    }

    async fn conversation(&'inner self) -> &'inner MlsConversation {
        &self.inner
    }
}

impl<D> ImmutableConversation<D> {
    pub(crate) fn new(inner: MlsConversation, client: Session<D>) -> Self {
        Self { inner, client }
    }
}
