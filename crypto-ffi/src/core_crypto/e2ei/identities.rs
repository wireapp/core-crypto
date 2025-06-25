use std::collections::HashMap;

use core_crypto::{RecursiveError, mls::conversation::Conversation as _};
#[cfg(target_family = "wasm")]
use wasm_bindgen::prelude::*;

use crate::{ConversationId, CoreCrypto, CoreCryptoResult, WireIdentity, client_id::ClientIdMaybeArc};

#[cfg(not(target_family = "wasm"))]
type DeviceIdentities = Vec<WireIdentity>;

#[cfg(target_family = "wasm")]
type DeviceIdentities = JsValue;

#[cfg(not(target_family = "wasm"))]
pub(crate) type UserIdentities = HashMap<String, Vec<WireIdentity>>;

#[cfg(target_family = "wasm")]
pub(crate) type UserIdentities = JsValue;

#[cfg_attr(not(target_family = "wasm"), uniffi::export)]
#[cfg_attr(target_family = "wasm", wasm_bindgen)]
impl CoreCrypto {
    /// See [core_crypto::mls::conversation::Conversation::get_device_identities]
    #[cfg_attr(target_family = "wasm", wasm_bindgen(unchecked_return_type = "WireIdentity[]"))]
    pub async fn get_device_identities(
        &self,
        conversation_id: &ConversationId,
        device_ids: Vec<ClientIdMaybeArc>,
    ) -> CoreCryptoResult<DeviceIdentities> {
        let conversation = self
            .inner
            .get_raw_conversation(conversation_id)
            .await
            .map_err(RecursiveError::mls_client("getting raw conversation"))?;
        let device_ids = device_ids.into_iter().map(|id| id.as_cc()).collect::<Vec<_>>();
        let wire_identities = conversation
            .get_device_identities(&device_ids)
            .await?
            .into_iter()
            .map(WireIdentity::from)
            .collect::<Vec<_>>();
        #[cfg(target_family = "wasm")]
        let wire_identities =
            serde_wasm_bindgen::to_value(&wire_identities).expect("device identities can always be serialized");
        Ok(wire_identities)
    }

    /// See [core_crypto::mls::conversation::Conversation::get_user_identities]
    #[cfg_attr(
        target_family = "wasm",
        wasm_bindgen(unchecked_return_type = "Map<string, WireIdentity[]>")
    )]
    pub async fn get_user_identities(
        &self,
        conversation_id: &ConversationId,
        user_ids: Vec<String>,
    ) -> CoreCryptoResult<UserIdentities> {
        let conversation = self
            .inner
            .get_raw_conversation(conversation_id)
            .await
            .map_err(RecursiveError::mls_client("getting raw conversation"))?;
        let identities = conversation.get_user_identities(user_ids.as_slice()).await?;
        let identities = identities
            .into_iter()
            .map(|(k, v)| (k, v.into_iter().map(WireIdentity::from).collect()))
            .collect::<HashMap<_, Vec<_>>>();
        #[cfg(target_family = "wasm")]
        let identities = serde_wasm_bindgen::to_value(&identities).expect("user identities can always be serialized");
        Ok(identities)
    }
}
