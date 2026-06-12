use std::{collections::HashMap, sync::Arc};

use core_crypto::RecursiveError;

use crate::{ClientId, ConversationId, CoreCryptoFfi, CoreCryptoResult, Uuid, WireIdentity};

type DeviceIdentities = Vec<WireIdentity>;

pub(crate) type UserIdentities = HashMap<Arc<Uuid>, Vec<WireIdentity>>;

#[uniffi::export]
impl CoreCryptoFfi {
    /// Returns the E2EI identity claims for the specified devices in the given conversation.
    pub async fn get_device_identities(
        &self,
        conversation_id: &ConversationId,
        device_ids: Vec<Arc<ClientId>>,
    ) -> CoreCryptoResult<DeviceIdentities> {
        let conversation = self
            .inner
            .mls_session()
            .await?
            .get_raw_conversation(conversation_id.as_ref())
            .await
            .map_err(RecursiveError::mls_client("getting raw conversation"))?;
        let device_ids = device_ids.iter().map(|c| c.as_ref().as_ref()).collect::<Vec<_>>();
        let wire_identities = conversation
            .get_device_identities(&device_ids)
            .await?
            .into_iter()
            .map(WireIdentity::from)
            .collect::<Vec<_>>();
        Ok(wire_identities)
    }

    /// Returns the E2EI identity claims for the specified users in the given conversation, grouped by user ID.
    pub async fn get_user_identities(
        &self,
        conversation_id: &ConversationId,
        user_ids: Vec<Arc<Uuid>>,
    ) -> CoreCryptoResult<UserIdentities> {
        let user_ids = user_ids.into_iter().map(|uuid| **uuid).collect::<Vec<_>>();
        let conversation = self
            .inner
            .mls_session()
            .await?
            .get_raw_conversation(conversation_id.as_ref())
            .await
            .map_err(RecursiveError::mls_client("getting raw conversation"))?;
        let identities = conversation.get_user_identities(&user_ids).await?;
        let identities = identities
            .into_iter()
            .map(|(k, v)| -> CoreCryptoResult<_> {
                let identities = v.into_iter().map(WireIdentity::from).collect::<Vec<_>>();
                Ok((Arc::new(k.into()), identities))
            })
            .collect::<CoreCryptoResult<HashMap<_, _>>>()?;
        Ok(identities)
    }
}
