use std::sync::Arc;

use crate::ConversationId;

/// see [core_crypto::WelcomeBundle]
#[derive(Debug, uniffi::Record)]
pub struct WelcomeBundle {
    /// Identifier of the joined conversation
    pub id: Arc<ConversationId>,
}

impl From<core_crypto::WelcomeBundle> for WelcomeBundle {
    fn from(core_crypto::WelcomeBundle { id, .. }: core_crypto::WelcomeBundle) -> Self {
        let id = Arc::new(id.into());
        Self { id }
    }
}
