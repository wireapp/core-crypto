use core_crypto::{RecursiveError, mls::conversation::Conversation as _};
#[cfg(target_family = "wasm")]
use wasm_bindgen::prelude::*;

use crate::{
    Ciphersuite, CoreCrypto, CoreCryptoResult,
    client_id::{ClientIdMaybeArc, client_id_from_cc},
};

// Note that we can't do the same `Box<[u8]>` thing here; it doesn't work for async functions.
#[cfg(target_family = "wasm")]
pub(crate) type ConversationId = js_sys::Uint8Array;

#[cfg(not(target_family = "wasm"))]
pub(crate) type ConversationId = Vec<u8>;

#[macro_export]
macro_rules! conversation_id_vec {
    ($conversation_id:expr) => {{
        #[cfg(target_family = "wasm")]
        {
            // unfortunate that `Uint8Array` doesn't give us a way to borrow a byte slice,
            // but apparently we have no lifetime guarantees so it's understandable
            $conversation_id.to_vec()
        }

        #[cfg(not(target_family = "wasm"))]
        {
            // it's kind of silly that we have to clone it here given that both
            // sides of the interface expect references, but that's unfortunately
            // the only way to make the macro / lifetimes all work out
            $conversation_id.to_owned()
        }
    }};
}

#[cfg_attr(not(target_family = "wasm"), uniffi::export)]
#[cfg_attr(target_family = "wasm", wasm_bindgen)]
impl CoreCrypto {
    /// See [core_crypto::mls::conversation::Conversation::epoch]
    pub async fn conversation_epoch(&self, conversation_id: &ConversationId) -> CoreCryptoResult<u64> {
        let conversation_id = conversation_id_vec!(conversation_id);
        let conversation = self
            .inner
            .get_raw_conversation(&conversation_id)
            .await
            .map_err(RecursiveError::mls_client("getting raw conversation by id"))?;
        Ok(conversation.epoch().await)
    }

    /// See [core_crypto::mls::conversation::Conversation::ciphersuite]
    pub async fn conversation_ciphersuite(&self, conversation_id: &ConversationId) -> CoreCryptoResult<Ciphersuite> {
        let conversation_id = conversation_id_vec!(conversation_id);
        let cs = self
            .inner
            .get_raw_conversation(&conversation_id)
            .await
            .map_err(RecursiveError::mls_client("getting raw conversation by id"))?
            .ciphersuite()
            .await;
        Ok(Ciphersuite::from(core_crypto::prelude::CiphersuiteName::from(cs)))
    }

    /// See [core_crypto::prelude::Session::conversation_exists]
    pub async fn conversation_exists(&self, conversation_id: &ConversationId) -> CoreCryptoResult<bool> {
        let conversation_id = conversation_id_vec!(conversation_id);
        self.inner
            .conversation_exists(&conversation_id)
            .await
            .map_err(RecursiveError::mls_client("getting conversation existence by id"))
            .map_err(Into::into)
    }

    /// See [core_crypto::mls::conversation::Conversation::get_client_ids]
    pub async fn get_client_ids(&self, conversation_id: &ConversationId) -> CoreCryptoResult<Vec<ClientIdMaybeArc>> {
        let conversation_id = conversation_id_vec!(conversation_id);
        let conversation = self
            .inner
            .get_raw_conversation(&conversation_id)
            .await
            .map_err(RecursiveError::mls_client("getting raw conversation"))?;
        Ok(conversation
            .get_client_ids()
            .await
            .into_iter()
            .map(client_id_from_cc)
            .collect())
    }

    /// See [core_crypto::mls::conversation::Conversation::get_external_sender]
    pub async fn get_external_sender(&self, conversation_id: &ConversationId) -> CoreCryptoResult<Vec<u8>> {
        let conversation_id = conversation_id_vec!(conversation_id);
        let conversation = self
            .inner
            .get_raw_conversation(&conversation_id)
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
        let conversation_id = conversation_id_vec!(conversation_id);
        self.inner
            .get_raw_conversation(&conversation_id)
            .await
            .map_err(RecursiveError::mls_client("getting raw conversation"))?
            .export_secret_key(key_length as usize)
            .await
            .map_err(Into::into)
    }

    /// See [core_crypto::mls::conversation::Conversation::is_history_sharing_enabled]
    pub async fn is_history_sharing_enabled(&self, conversation_id: &ConversationId) -> CoreCryptoResult<bool> {
        let conversation_id = conversation_id_vec!(conversation_id);
        let conversation = self
            .inner
            .get_raw_conversation(&conversation_id)
            .await
            .map_err(RecursiveError::mls_client("getting raw conversation"))?;
        Ok(conversation.is_history_sharing_enabled().await)
    }
}
