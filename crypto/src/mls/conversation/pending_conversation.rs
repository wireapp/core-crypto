use super::Result;
use crate::RecursiveError;
use crate::context::CentralContext;
use core_crypto_keystore::entities::PersistedMlsPendingGroup;
use mls_crypto_provider::MlsCryptoProvider;

/// A pending conversation is a conversation that has been created via an external join commit
/// locally, while this commit has not yet been approved by the DS.
pub(crate) struct PendingConversation {
    inner: PersistedMlsPendingGroup,
    context: CentralContext,
}

impl PendingConversation {
    pub(crate) fn new(inner: PersistedMlsPendingGroup, context: CentralContext) -> Self {
        Self { inner, context }
    }

    async fn mls_provider(&self) -> Result<MlsCryptoProvider> {
        self.context
            .mls_provider()
            .await
            .map_err(RecursiveError::root("getting mls provider"))
            .map_err(Into::into)
    }

    fn id(&self) -> &ConversationId {
        &self.inner.id
    }
}
