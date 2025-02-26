use super::Error;
use super::ImmutableConversation;
use super::Result;
use crate::RecursiveError;
use crate::e2e_identity::conversation_state::compute_state;
use crate::prelude::{ClientId, E2eiConversationState, MlsCredentialType, WireIdentity};
use openmls_traits::OpenMlsCryptoProvider;
use std::collections::HashMap;

impl ImmutableConversation {
    /// See [`crate::mls::conversation::ConversationGuard::e2ei_conversation_state`].
    pub async fn e2ei_conversation_state(&self) -> Result<E2eiConversationState> {
        self.mls_provider()
            .authentication_service()
            .refresh_time_of_interest()
            .await;
        let inner = self.conversation();
        Ok(compute_state(
            inner.ciphersuite(),
            inner.group.members_credentials(),
            MlsCredentialType::X509,
            self.mls_provider().authentication_service().borrow().await.as_ref(),
        )
        .await)
    }

    /// See [`crate::mls::conversation::ConversationGuard::get_device_identities`].
    pub async fn get_device_identities(&self, device_ids: &[ClientId]) -> Result<Vec<WireIdentity>> {
        if device_ids.is_empty() {
            return Err(Error::CallerError(
                "This function accepts a list of IDs as a parameter, but that list was empty.",
            ));
        }
        let mls_provider = self.mls_provider();
        let auth_service = mls_provider.authentication_service();
        auth_service.refresh_time_of_interest().await;
        let auth_service = auth_service.borrow().await;
        let env = auth_service.as_ref();
        let conversation = self.conversation();
        conversation
            .get_device_identities(device_ids, env)
            .map_err(RecursiveError::e2e_identity("getting device identities"))
            .map_err(Into::into)
    }

    /// See [`crate::mls::conversation::ConversationGuard::get_user_identities`].
    pub async fn get_user_identities(&self, user_ids: &[String]) -> Result<HashMap<String, Vec<WireIdentity>>> {
        if user_ids.is_empty() {
            return Err(Error::CallerError(
                "This function accepts a list of IDs as a parameter, but that list was empty.",
            ));
        }
        let mls_provider = self.mls_provider();
        let auth_service = mls_provider.authentication_service();
        auth_service.refresh_time_of_interest().await;
        let auth_service = auth_service.borrow().await;
        let env = auth_service.as_ref();
        let conversation = self.conversation();

        conversation
            .get_user_identities(user_ids, env)
            .map_err(RecursiveError::e2e_identity("getting user identities"))
            .map_err(Into::into)
    }
}
