//! This module contains all [super::TransactionContext] methods related to a conversation.

pub mod external_commit;
mod persistence;
pub mod welcome;

use core_crypto_keystore::{entities::PersistedMlsPendingGroup, traits::FetchFromDatabase as _};
use openmls::group::MlsGroup;

use super::{Error, Result, TransactionContext};
use crate::{
    ConversationConfiguration, CredentialRef, KeystoreError, LeafError, OpenMlsError, RecursiveError,
    mls::conversation::{ConversationIdRef, ConversationMut, PendingConversation},
};

impl TransactionContext {
    /// Checks if a given conversation id exists locally.
    ///
    /// Somewhat cheaper than `self.conversation(id).is_ok()`.
    pub async fn conversation_exists(&self, id: &ConversationIdRef) -> Result<bool> {
        let database = self.database().await?.into();
        self.mls_groups()
            .await?
            .exists(id, &database)
            .await
            .map_err(RecursiveError::root("checking for conversation existence"))
            .map_err(Into::into)
    }

    /// Acquire a conversation guard.
    ///
    /// This helper struct permits mutations on a conversation.
    pub async fn conversation(&self, id: &ConversationIdRef) -> Result<ConversationMut> {
        self.conversation_maybe(id)
            .await?
            .ok_or_else(|| LeafError::ConversationNotFound(id.to_owned()).into())
    }

    /// Acquire a conversation guard if the conversation exists.
    ///
    /// This helper struct permits mutations on a conversation.
    pub async fn conversation_maybe(&self, id: &ConversationIdRef) -> Result<Option<ConversationMut>> {
        let keystore = self.database().await?;
        let session = self.session().await?;
        let inner = self
            .mls_groups()
            .await?
            .get_or_fetch(id, &keystore, session)
            .await
            .map_err(RecursiveError::root("fetching conversation from mls groups by id"))?;

        if let Some(inner) = inner {
            return Ok(Some(ConversationMut::new(inner, self.clone())));
        }

        // Check if there is a pending conversation with the same id
        if let Some(pending) = self.pending_conversation(id).await? {
            return Err(Error::PendingConversation(pending));
        }

        Ok(None)
    }

    pub(crate) async fn pending_conversation(&self, id: &ConversationIdRef) -> Result<Option<PendingConversation>> {
        let keystore = self.database().await?;
        let Some(pending_group) = keystore
            .get_borrowed::<PersistedMlsPendingGroup>(id.as_ref())
            .await
            .map_err(KeystoreError::wrap("finding persisted mls pending group"))?
        else {
            return Ok(None);
        };

        let pending_conversation = PendingConversation::new(pending_group, self.clone());
        Ok(Some(pending_conversation))
    }

    /// Create a new empty conversation
    ///
    /// # Arguments
    /// * `id` - identifier of the group/conversation (must be unique otherwise the existing group will be overridden)
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
        credential_ref: &CredentialRef,
        configuration: ConversationConfiguration,
    ) -> Result<()> {
        let database = self.database().await?;
        let provider = self.crypto_provider().await?;
        if self.conversation_exists(id).await? || self.pending_conversation_exists(id).await? {
            return Err(LeafError::ConversationAlreadyExists(id.to_owned()).into());
        }

        let credential = credential_ref
            .load(&*database)
            .await
            .map_err(RecursiveError::mls_credential_ref(
                "loading credential from database to create new conversation",
            ))?;

        let config = configuration
            .as_openmls_default_configuration()
            .map_err(RecursiveError::mls_conversation("converting config to openmls default"))?;

        let group = MlsGroup::new_with_group_id(
            &provider,
            &credential.signature_key_pair,
            &config,
            openmls::prelude::GroupId::from_slice(id.as_ref()),
            credential.to_mls_credential_with_key(),
        )
        .await
        .map_err(OpenMlsError::wrap("creating group with id"))?;

        self.persist_conversation_from_mls_group(group, configuration).await?;

        Ok(())
    }
}
