//! This module contains all [super::TransactionContext] methods related to a conversation.

pub mod external_commit;
mod persistence;
pub mod welcome;

use std::sync::Arc;

use core_crypto_keystore::{entities::PersistedMlsGroup, traits::FetchFromDatabase as _};
use openmls::group::MlsGroup;

use super::{Error, Result, TransactionContext};
use crate::{
    ConversationConfiguration, CredentialRef, KeystoreError, OpenMlsError, RecursiveError,
    mls::conversation::{ConversationIdRef, ConversationMut, PendingConversation},
};

impl TransactionContext {
    /// Checks if a given conversation id exists locally.
    ///
    /// Somewhat cheaper than `self.conversation(id).is_ok()`.
    pub async fn conversation_exists(&self, id: &ConversationIdRef) -> Result<bool> {
        let database = self.database()?.into();
        self.mls_groups()
            .await?
            .exists(id, &database)
            .await
            .map_err(RecursiveError::context("checking for conversation existence"))
            .map_err(Into::into)
    }

    /// Acquire a conversation guard.
    ///
    /// This helper struct permits mutations on a conversation.
    pub async fn conversation(&self, id: &ConversationIdRef) -> Result<ConversationMut> {
        let inner = self.inner()?;
        let session = self.session().await?;
        let conversation = self
            .mls_groups()
            .await?
            .get_or_fetch(id, &inner.transaction, session)
            .await
            .map_err(RecursiveError::context("fetching conversation from mls groups by id"))?;

        if let Some(conversation) = conversation {
            return Ok(ConversationMut::new(conversation, self.clone()));
        }
        // Check if there is a pending conversation with
        // the same id
        let pending = self.pending_conversation(id).await.map(Error::PendingConversation)?;
        Err(pending)
    }

    pub(crate) async fn pending_conversation(&self, id: &ConversationIdRef) -> Result<PendingConversation> {
        let inner = self.inner()?;
        let group = inner
            .transaction
            .get_borrowed::<PersistedMlsGroup>(id.keystore())
            .await
            .map_err(KeystoreError::wrap("finding persisted mls group"))?
            .filter(|group| group.is_pending);
        let Some(group) = group else {
            return Err(Error::ConversationNotFound(id.to_owned()));
        };
        let group = Arc::unwrap_or_clone(group);
        Ok(PendingConversation::new(group, self.clone()))
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
        if self.conversation_exists(id).await? || self.pending_conversation_exists(id).await? {
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
            .transaction()
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
