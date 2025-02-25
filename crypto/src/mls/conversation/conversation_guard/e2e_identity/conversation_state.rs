//! This module provides the implementation of the `ConversationGuard` for the E2E identity
//! conversation state.
//!
//! Even though this is just a single method now, we want it in its own module: after the upcoming
//! internal refactoring, this is probably the place where almost all the logic from
//! [crate::e2e_identity::conversation_state] will be moved to.

use crate::prelude::MlsCredentialType;

use openmls_traits::OpenMlsCryptoProvider;

use super::ConversationGuard;
use super::Result;
use crate::e2e_identity::conversation_state::compute_state;
use crate::prelude::E2eiConversationState;

impl ConversationGuard {
    /// Indicates when to mark a conversation as not verified i.e. when not all its members have a X509
    /// Credential generated by Wire's end-to-end identity enrollment
    pub async fn e2ei_conversation_state(&self) -> Result<E2eiConversationState> {
        let backend = self.mls_provider().await?;
        let authentication_service = backend.authentication_service();
        authentication_service.refresh_time_of_interest().await;
        let inner = self.conversation().await;
        let state = compute_state(
            inner.ciphersuite(),
            inner.group.members_credentials(),
            MlsCredentialType::X509,
            authentication_service.borrow().await.as_ref(),
        )
        .await;
        Ok(state)
    }
}
