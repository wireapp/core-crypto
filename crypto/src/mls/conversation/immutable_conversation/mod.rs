use super::{ConversationWithMls, MlsConversation, Result};
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
impl<'inner> ConversationWithMls<'inner> for ImmutableConversation {
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
}
