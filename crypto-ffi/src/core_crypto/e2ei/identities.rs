use std::collections::HashMap;

use core_crypto::{RecursiveError, mls::conversation::Conversation as _};

use crate::{ConversationId, CoreCryptoFfi, CoreCryptoResult, WireIdentity, client_id::ClientIdMaybeArc};

type DeviceIdentities = Vec<WireIdentity>;

pub(crate) type UserIdentities = HashMap<String, Vec<WireIdentity>>;

#[uniffi::export]
impl CoreCryptoFfi {
    /// See [core_crypto::mls::conversation::Conversation::get_device_identities]
    pub async fn get_device_identities(
        &self,
        conversation_id: &ConversationId,
        device_ids: Vec<ClientIdMaybeArc>,
    ) -> CoreCryptoResult<DeviceIdentities> {
        let conversation = self
            .inner
            .get_raw_conversation(conversation_id.as_ref())
            .await
            .map_err(RecursiveError::mls_client("getting raw conversation"))?;
        let device_ids = device_ids.into_iter().map(|id| id.as_cc()).collect::<Vec<_>>();
        let wire_identities = conversation
            .get_device_identities(&device_ids)
            .await?
            .into_iter()
            .map(WireIdentity::from)
            .collect::<Vec<_>>();
        Ok(wire_identities)
    }

    /// See [core_crypto::mls::conversation::Conversation::get_user_identities]
    pub async fn get_user_identities(
        &self,
        conversation_id: &ConversationId,
        user_ids: Vec<String>,
    ) -> CoreCryptoResult<UserIdentities> {
        let conversation = self
            .inner
            .get_raw_conversation(conversation_id.as_ref())
            .await
            .map_err(RecursiveError::mls_client("getting raw conversation"))?;
        let identities = conversation.get_user_identities(user_ids.as_slice()).await?;
        let identities = identities
            .into_iter()
            .map(|(k, v)| -> CoreCryptoResult<_> {
                let identities = v.into_iter().map(WireIdentity::from).collect::<Vec<_>>();
                Ok((k, identities))
            })
            .collect::<CoreCryptoResult<HashMap<_, _>>>()?;
        Ok(identities)
    }
}
