mod e2e_identity;

use super::{Error, MlsConversation, Result};
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
}
