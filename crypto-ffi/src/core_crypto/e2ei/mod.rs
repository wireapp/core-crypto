use core_crypto::{RecursiveError, mls::conversation::Conversation as _};

use crate::{Ciphersuite, ConversationId, CoreCryptoFfi, CoreCryptoResult, E2eiConversationState};

pub(crate) mod identities;

// End-to-end identity methods
#[uniffi::export]
impl CoreCryptoFfi {
    /// See [core_crypto::Session::e2ei_is_pki_env_setup]
    pub async fn e2ei_is_pki_env_setup(&self) -> bool {
        if let Some(pki_env) = self.inner.get_pki_environment().await {
            return pki_env.provider_is_setup().await;
        };

        false
    }

    /// See [core_crypto::Session::e2ei_is_enabled]
    pub async fn e2ei_is_enabled(&self, ciphersuite: Ciphersuite) -> CoreCryptoResult<bool> {
        self.inner
            .mls_session()
            .await?
            .e2ei_is_enabled(ciphersuite.into())
            .await
            .map_err(RecursiveError::mls_client("checking if e2ei is enabled"))
            .map_err(Into::into)
    }

    /// See [core_crypto::mls::conversation::Conversation::e2ei_conversation_state]
    pub async fn e2ei_conversation_state(
        &self,
        conversation_id: &ConversationId,
    ) -> CoreCryptoResult<E2eiConversationState> {
        self.inner
            .mls_session()
            .await?
            .get_raw_conversation(conversation_id.as_ref())
            .await
            .map_err(RecursiveError::mls_client("getting conversation by id"))?
            .e2ei_conversation_state()
            .await
            .map(Into::into)
            .map_err(Into::into)
    }
}
