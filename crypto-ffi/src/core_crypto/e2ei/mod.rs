use core_crypto::{RecursiveError, mls::conversation::Conversation as _};
#[cfg(target_family = "wasm")]
use wasm_bindgen::prelude::*;

use crate::{Ciphersuite, ConversationId, CoreCrypto, CoreCryptoResult, E2eiConversationState};

pub(crate) mod identities;

// End-to-end identity methods
#[cfg_attr(target_family = "wasm", wasm_bindgen)]
#[cfg_attr(not(target_family = "wasm"), uniffi::export)]
impl CoreCrypto {
    /// See [core_crypto::prelude::Session::e2ei_is_pki_env_setup]
    pub async fn e2ei_is_pki_env_setup(&self) -> bool {
        self.inner.e2ei_is_pki_env_setup().await
    }

    /// See [core_crypto::prelude::Session::e2ei_is_enabled]
    pub async fn e2ei_is_enabled(&self, ciphersuite: Ciphersuite) -> CoreCryptoResult<bool> {
        let signature_scheme =
            core_crypto::prelude::MlsCiphersuite::from(core_crypto::prelude::CiphersuiteName::from(ciphersuite))
                .signature_algorithm();
        self.inner
            .e2ei_is_enabled(signature_scheme)
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
            .get_raw_conversation(conversation_id)
            .await
            .map_err(RecursiveError::mls_client("getting conversation by id"))?
            .e2ei_conversation_state()
            .await
            .map(Into::into)
            .map_err(Into::into)
    }
}
