//! This module contains all [super::TransactionContext] methods related to a conversation.

pub mod external_commit;
mod persistence;
pub mod welcome;

use openmls::group::MlsGroup;

use super::{Error, Result, TransactionContext};
use crate::{
    ConversationConfiguration, CredentialRef, OpenMlsError, RecursiveError,
    mls::conversation::{ConversationIdRef, ConversationMut},
};

impl TransactionContext {
    /// Checks if a given conversation id exists locally.
    ///
    /// Somewhat cheaper than `self.conversation(id).is_ok()`.
    ///
    /// If `filter_pending` is set, only returns `true` if a conversation exists whose `is_pending`
    /// matches the filter.
    pub async fn conversation_exists(&self, id: &ConversationIdRef, filter_pending: Option<bool>) -> Result<bool> {
        let database = self.database()?.into();
        self.mls_groups()
            .await?
            .exists(id, &database, filter_pending)
            .await
            .map_err(RecursiveError::context("checking for conversation existence"))
            .map_err(Into::into)
    }

    /// Acquire a conversation guard.
    ///
    /// Most of the time it's better to use [`Self::conversation`] or [`Self::pending_conversation`].
    /// However, in certain limited circumstances, it might be necessary to get a [`ConversationMut`]
    /// whether or not the conversation in question is in fact pending.
    pub(crate) async fn conversation_regardless_of_pending_status(
        &self,
        id: &ConversationIdRef,
    ) -> Result<ConversationMut> {
        let inner = self.inner()?;
        let session = self.session().await?;
        let conversation = self
            .mls_groups()
            .await?
            .get_or_fetch(id, &inner.transaction, &session)
            .await
            .map_err(RecursiveError::context("fetching conversation from mls groups by id"))?
            .ok_or_else(|| Error::ConversationNotFound(id.to_owned()))?;
        Ok(ConversationMut::new(conversation, self.clone()))
    }

    /// Acquire a conversation guard.
    ///
    /// This helper struct permits mutations on a conversation.
    pub async fn conversation(&self, id: &ConversationIdRef) -> Result<ConversationMut> {
        let conversation = self.conversation_regardless_of_pending_status(id).await?;
        if conversation.group().await.is_pending {
            return Err(Error::PendingConversation(id.to_owned()));
        }
        Ok(conversation)
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
        let database = self.database()?;
        let provider = self.crypto_provider().await?;
        if self.conversation_exists(id, None).await? {
            return Err(Error::ConversationAlreadyExists(id.to_owned()));
        }

        let credential = credential_ref.load(&*database).await.map_err(RecursiveError::context(
            "loading credential from database to create new conversation",
        ))?;

        let config = configuration
            .as_openmls_default_configuration()
            .map_err(RecursiveError::context("converting config to openmls default"))?;

        // there's a deferred constraint on epoch encryption keypairs.
        // openmls creates the keypairs before it hands us the `group` which we can use to
        // persist the conversation, so the constraint _can't_ be fulfilled immediately;
        // it gets checked at the outermost commit.
        // wrapping these two operations in an explicit savepoint means that these two operations
        // are bundled together; failing to persist the group un-persists the keypairs.
        self.inner()?
            .with_savepoint(
                "new_conversation",
                async || {
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
                },
                Error::savepoint,
            )
            .await
    }
}
