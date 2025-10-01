//! This module contains all [super::TransactionContext] methods related to a conversation.

pub mod external_commit;
mod external_proposal;
pub mod external_sender;
pub(crate) mod proposal;
pub mod welcome;

use core_crypto_keystore::{connection::FetchFromDatabase as _, entities::PersistedMlsPendingGroup};

use super::{Error, Result, TransactionContext};
use crate::{
    KeystoreError, LeafError, MlsConversation, MlsConversationConfiguration, MlsCredentialType, RecursiveError,
    mls::conversation::{ConversationGuard, ConversationIdRef, pending_conversation::PendingConversation},
};

impl TransactionContext {
    /// Acquire a conversation guard.
    ///
    /// This helper struct permits mutations on a conversation.
    pub async fn conversation(&self, id: &ConversationIdRef) -> Result<ConversationGuard> {
        let keystore = self.mls_provider().await?.keystore();
        let inner = self
            .mls_groups()
            .await?
            .get_fetch(id, &keystore, None)
            .await
            .map_err(RecursiveError::root("fetching conversation from mls groups by id"))?;

        if let Some(inner) = inner {
            return Ok(ConversationGuard::new(inner, self.clone()));
        }
        // Check if there is a pending conversation with
        // the same id
        let pending = self.pending_conversation(id).await.map(Error::PendingConversation)?;
        Err(pending)
    }

    pub(crate) async fn pending_conversation(&self, id: &ConversationIdRef) -> Result<PendingConversation> {
        let keystore = self.keystore().await?;
        let Some(pending_group) = keystore
            .find::<PersistedMlsPendingGroup>(id)
            .await
            .map_err(KeystoreError::wrap("finding persisted mls pending group"))?
        else {
            return Err(LeafError::ConversationNotFound(id.to_owned()).into());
        };
        Ok(PendingConversation::new(pending_group, self.clone()))
    }

    /// Create a new empty conversation
    ///
    /// # Arguments
    /// * `id` - identifier of the group/conversation (must be unique otherwise the existing group
    ///   will be overridden)
    /// * `creator_credential_type` - kind of credential the creator wants to create the group with
    /// * `config` - configuration of the group/conversation
    ///
    /// # Errors
    /// Errors can happen from the KeyStore or from OpenMls for ex if no [openmls::key_packages::KeyPackage] can
    /// be found in the KeyStore
    #[cfg_attr(test, crate::dispotent)]
    pub async fn new_conversation(
        &self,
        id: &ConversationIdRef,
        creator_credential_type: MlsCredentialType,
        config: MlsConversationConfiguration,
    ) -> Result<()> {
        if self.conversation_exists(id).await? || self.pending_conversation_exists(id).await? {
            return Err(LeafError::ConversationAlreadyExists(id.to_owned()).into());
        }
        let conversation = MlsConversation::create(
            id.to_owned(),
            &self.session().await?,
            creator_credential_type,
            config,
            &self.mls_provider().await?,
        )
        .await
        .map_err(RecursiveError::mls_conversation("creating conversation"))?;

        self.mls_groups().await?.insert(id, conversation);

        Ok(())
    }

    /// Checks if a given conversation id exists locally
    pub async fn conversation_exists(&self, id: &ConversationIdRef) -> Result<bool> {
        self.mls_groups()
            .await?
            .get_fetch(id, &self.mls_provider().await?.keystore(), None)
            .await
            .map(|option| option.is_some())
            .map_err(RecursiveError::root("fetching conversation from mls groups by id"))
            .map_err(Into::into)
    }
}
