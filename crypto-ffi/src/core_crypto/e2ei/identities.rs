use std::collections::HashMap;

use core_crypto::{RecursiveError, mls::conversation::Conversation as _, prelude::VerifiableGroupInfo};
use tls_codec::Deserialize as _;
#[cfg(target_family = "wasm")]
use wasm_bindgen::prelude::*;

use crate::{
    ClientId, ConversationId, CoreCrypto, CoreCryptoResult, CredentialType, E2eiConversationState, WireIdentity,
    conversation_id_vec,
};

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
        device_ids: Vec<ClientId>,
    ) -> CoreCryptoResult<DeviceIdentities> {
        let conversation_id = conversation_id_vec!(conversation_id);
        let conversation = self
            .inner
            .get_raw_conversation(&conversation_id)
            .await
            .map_err(RecursiveError::mls_client("getting raw conversation"))?;
        let device_ids = device_ids.into_iter().map(|ClientId(id)| id).collect::<Vec<_>>();
        let device_identities = conversation.get_device_identities(&device_ids).await?;
        let device_identities = device_identities
            .into_iter()
            .map(WireIdentity::from)
            .collect::<Vec<_>>();
        #[cfg(target_family = "wasm")]
        let device_identities =
            serde_wasm_bindgen::to_value(&device_identities).expect("device identities can always be serialized");
        Ok(device_identities)
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
        let conversation_id = conversation_id_vec!(conversation_id);
        let conversation = self
            .inner
            .get_raw_conversation(&conversation_id)
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

    /// See [core_crypto::prelude::Session::get_credential_in_use]
    pub async fn get_credential_in_use(
        &self,
        group_info: Vec<u8>,
        credential_type: CredentialType,
    ) -> CoreCryptoResult<E2eiConversationState> {
        let group_info = VerifiableGroupInfo::tls_deserialize(&mut group_info.as_slice())
            .map_err(core_crypto::mls::conversation::Error::tls_deserialize(
                "verifiable group info",
            ))
            .map_err(RecursiveError::mls_conversation("deserializing veriable group info"))?;
        self.inner
            .get_credential_in_use(group_info, credential_type.into())
            .await
            .map(Into::into)
            .map_err(RecursiveError::mls_client("getting credential in use"))
            .map_err(Into::into)
    }
}
