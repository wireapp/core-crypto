use core_crypto::{RecursiveError, mls::conversation::Conversation as _};

use crate::{CipherSuite, ConversationId, CoreCryptoFfi, CoreCryptoResult, E2eiConversationState};

pub(crate) mod identities;

// End-to-end identity methods
#[uniffi::export]
impl CoreCryptoFfi {
    /// Returns true if the PKI environment has been set up and its provider is configured.
    pub async fn e2ei_is_pki_env_setup(&self) -> bool {
        if let Some(pki_env) = self.inner.get_pki_environment().await {
            return pki_env.provider_is_setup().await;
        };

        false
    }

    /// Returns true if end-to-end identity is enabled for the given ciphersuite.
    pub async fn e2ei_is_enabled(&self, ciphersuite: CipherSuite) -> CoreCryptoResult<bool> {
        self.inner
            .mls_session()
            .await?
            .e2ei_is_enabled(ciphersuite.into())
            .await
            .map_err(RecursiveError::mls_client("checking if e2ei is enabled"))
            .map_err(Into::into)
    }

    /// Returns the end-to-end identity verification state of the given conversation.
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
