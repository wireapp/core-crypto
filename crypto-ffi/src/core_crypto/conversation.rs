use core_crypto::{RecursiveError, mls::conversation::Conversation as _};
#[cfg(target_family = "wasm")]
use wasm_bindgen::prelude::*;

use crate::{
    Ciphersuite, ClientId, CoreCrypto, CoreCryptoResult, bytes_wrapper::bytes_wrapper, client_id::ClientIdMaybeArc,
};

bytes_wrapper!(
    /// A unique identifier for a single conversation.
    ///
    /// The backend provides an opaque string identifying a new conversation.
    /// Construct an instance of this newtype to pass that identifier to Rust.
    #[derive(Debug, Clone)]
    #[cfg_attr(target_family = "wasm", derive(serde::Serialize, serde::Deserialize))]
    #[cfg_attr(not(target_family = "wasm"), uniffi::export(Debug))]
    ConversationId
);

#[cfg_attr(not(target_family = "wasm"), uniffi::export)]
#[cfg_attr(target_family = "wasm", wasm_bindgen)]
impl CoreCrypto {
    /// See [core_crypto::mls::conversation::Conversation::epoch]
    pub async fn conversation_epoch(&self, conversation_id: &ConversationId) -> CoreCryptoResult<u64> {
        let conversation = self
            .inner
            .get_raw_conversation(conversation_id)
            .await
            .map_err(RecursiveError::mls_client("getting raw conversation by id"))?;
        Ok(conversation.epoch().await)
    }

    /// See [core_crypto::mls::conversation::Conversation::ciphersuite]
    pub async fn conversation_ciphersuite(&self, conversation_id: &ConversationId) -> CoreCryptoResult<Ciphersuite> {
        let cs = self
            .inner
            .get_raw_conversation(conversation_id)
            .await
            .map_err(RecursiveError::mls_client("getting raw conversation by id"))?
            .ciphersuite()
            .await;
        Ok(Ciphersuite::from(core_crypto::prelude::CiphersuiteName::from(cs)))
    }

    /// See [core_crypto::prelude::Session::conversation_exists]
    pub async fn conversation_exists(&self, conversation_id: &ConversationId) -> CoreCryptoResult<bool> {
        self.inner
            .conversation_exists(conversation_id)
            .await
            .map_err(RecursiveError::mls_client("getting conversation existence by id"))
            .map_err(Into::into)
    }

    /// See [core_crypto::mls::conversation::Conversation::get_client_ids]
    pub async fn get_client_ids(&self, conversation_id: &ConversationId) -> CoreCryptoResult<Vec<ClientIdMaybeArc>> {
        let conversation = self
            .inner
            .get_raw_conversation(conversation_id)
            .await
            .map_err(RecursiveError::mls_client("getting raw conversation"))?;
        Ok(conversation
            .get_client_ids()
            .await
            .into_iter()
            .map(ClientId::from_cc)
            .collect())
    }

    /// See [core_crypto::mls::conversation::Conversation::get_external_sender]
    pub async fn get_external_sender(&self, conversation_id: &ConversationId) -> CoreCryptoResult<Vec<u8>> {
        let conversation = self
            .inner
            .get_raw_conversation(conversation_id)
            .await
            .map_err(RecursiveError::mls_client("getting raw conversation"))?;
        conversation.get_external_sender().await.map_err(Into::into)
    }

    /// See [core_crypto::mls::conversation::Conversation::export_secret_key]
    pub async fn export_secret_key(
        &self,
        conversation_id: &ConversationId,
        key_length: u32,
    ) -> CoreCryptoResult<Vec<u8>> {
        self.inner
            .get_raw_conversation(conversation_id)
            .await
            .map_err(RecursiveError::mls_client("getting raw conversation"))?
            .export_secret_key(key_length as usize)
            .await
            .map_err(Into::into)
    }

    /// See [core_crypto::mls::conversation::Conversation::is_history_sharing_enabled]
    pub async fn is_history_sharing_enabled(&self, conversation_id: &ConversationId) -> CoreCryptoResult<bool> {
        let conversation = self
            .inner
            .get_raw_conversation(conversation_id)
            .await
            .map_err(RecursiveError::mls_client("getting raw conversation"))?;
        Ok(conversation.is_history_sharing_enabled().await)
    }
}
