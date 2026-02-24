use std::{collections::HashMap, sync::Arc};

use core_crypto::{mls::conversation::Conversation as _, transaction_context::Error as TransactionError};

use crate::{
    Ciphersuite, ClientId, ConversationId, CoreCryptoContext, CoreCryptoResult, E2eiConversationState, UserIdentities,
    WireIdentity,
};

#[uniffi::export]
impl CoreCryptoContext {
    /// See [core_crypto::mls::conversation::Conversation::e2ei_conversation_state]
    pub async fn e2ei_conversation_state(
        &self,
        conversation_id: &ConversationId,
    ) -> CoreCryptoResult<E2eiConversationState> {
        let conversation = self.inner.conversation(conversation_id.as_ref()).await?;
        conversation
            .e2ei_conversation_state()
            .await
            .map(Into::into)
            .map_err(Into::into)
    }

    /// See [core_crypto::Session::e2ei_is_enabled]
    pub async fn e2ei_is_enabled(&self, ciphersuite: Ciphersuite) -> CoreCryptoResult<bool> {
        self.inner
            .e2ei_is_enabled(ciphersuite.into())
            .await
            .map_err(Into::<TransactionError>::into)
            .map_err(Into::into)
    }

    /// See [core_crypto::mls::conversation::Conversation::get_device_identities]
    pub async fn get_device_identities(
        &self,
        conversation_id: &ConversationId,
        device_ids: Vec<Arc<ClientId>>,
    ) -> CoreCryptoResult<Vec<WireIdentity>> {
        let device_ids = device_ids.iter().map(|c| c.as_ref().as_ref()).collect::<Vec<_>>();

        let conversation = self.inner.conversation(conversation_id.as_ref()).await?;
        let wire_ids = conversation.get_device_identities(device_ids.as_slice()).await?;
        Ok(wire_ids.into_iter().map(Into::into).collect())
    }

    /// See [core_crypto::mls::conversation::Conversation::get_user_identities]
    pub async fn get_user_identities(
        &self,
        conversation_id: &ConversationId,
        user_ids: Vec<String>,
    ) -> CoreCryptoResult<UserIdentities> {
        let conversation = self.inner.conversation(conversation_id.as_ref()).await?;
        let user_ids = conversation.get_user_identities(user_ids.as_slice()).await?;
        let user_ids = user_ids
            .into_iter()
            .map(|(k, v)| -> CoreCryptoResult<_> {
                let identities = v.into_iter().map(WireIdentity::from).collect::<Vec<_>>();
                Ok((k, identities))
            })
            .collect::<CoreCryptoResult<HashMap<_, _>>>()?;
        Ok(user_ids)
    }

    /// See [core_crypto::Session::e2ei_is_pki_env_setup]
    pub async fn e2ei_is_pki_env_setup(&self) -> bool {
        self.inner.e2ei_is_pki_env_setup().await
    }
}
