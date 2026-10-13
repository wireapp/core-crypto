use core_crypto::RecursiveError;

use crate::{ConversationId, CoreCryptoFfi, CoreCryptoResult, E2eiConversationState};

pub(crate) mod identities;

// End-to-end identity methods
#[uniffi::export]
impl CoreCryptoFfi {
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
            .map_err(RecursiveError::context("getting conversation by id"))?
            .e2ei_conversation_state()
            .await
            .map(Into::into)
            .map_err(Into::into)
    }
}
