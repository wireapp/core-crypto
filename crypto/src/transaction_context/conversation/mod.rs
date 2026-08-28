//! This module contains all [super::TransactionContext] methods related to a conversation.

pub mod external_commit;
mod persistence;
pub mod welcome;

use std::sync::Arc;

use core_crypto_keystore::{
    entities::{MlsPendingMessage, PersistedMlsGroup, PersistedMlsPendingGroup, StoredBufferedCommit},
    traits::FetchFromDatabase as _,
};
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
        let database = self.database().await?.into();
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
        let inner = self.inner().await?;
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

    /// Discard everything buffered for a conversation which no longer exists in any form.
    ///
    /// Buffered messages and buffered commits are keyed by conversation id, and both are only ever
    /// read on behalf of a conversation. Once no conversation holds that id, they are unreachable:
    /// nothing can restore them and nothing else will ever delete them. So whichever operation
    /// removes the last trace of a conversation has to take its buffers along, and this is that
    /// step.
    ///
    /// The check is not redundant. One conversation id can name a group in `mls_groups` and a
    /// pending group in `mls_pending_groups` at the same time — that is what rejoining a
    /// conversation by external commit looks like — so removing one of the two does not on its own
    /// make the buffers garbage. Clearing unconditionally would discard messages the surviving
    /// conversation is still going to replay.
    ///
    /// Callers must have staged their own deletion before calling this, since that deletion is
    /// exactly what this reads back. It is also the reason this consults the keystore rather than
    /// [`Self::conversation_exists`]: the question is which rows will exist once the transaction
    /// commits, which the in-memory conversation cache does not answer.
    pub(crate) async fn clear_orphaned_conversation_buffers(&self, id: &ConversationIdRef) -> Result<()> {
        let inner = self.inner().await?;
        let tx = inner.transaction();

        let group_exists = tx
            .get_borrowed::<PersistedMlsGroup>(id.as_ref())
            .await
            .map_err(KeystoreError::wrap("looking for a group of a removed conversation"))?
            .is_some();
        let pending_group_exists = tx
            .get_borrowed::<PersistedMlsPendingGroup>(id.into())
            .await
            .map_err(KeystoreError::wrap(
                "looking for a pending group of a removed conversation",
            ))?
            .is_some();
        if group_exists || pending_group_exists {
            return Ok(());
        }

        tx.bulk_remove::<MlsPendingMessage, _>(id.into()).await;

        tx.remove_borrowed::<StoredBufferedCommit>(id.as_ref())
            .await
            .map_err(KeystoreError::wrap(
                "clearing the buffered commit of a removed conversation",
            ))?;

        Ok(())
    }

    pub(crate) async fn pending_conversation(&self, id: &ConversationIdRef) -> Result<PendingConversation> {
        let inner = self.inner().await?;
        let Some(pending_group) = inner
            .transaction
            .get_borrowed::<PersistedMlsPendingGroup>(id.into())
            .await
            .map_err(KeystoreError::wrap("finding persisted mls pending group"))?
        else {
            return Err(Error::ConversationNotFound(id.to_owned()));
        };
        let pending_group = Arc::unwrap_or_clone(pending_group);
        Ok(PendingConversation::new(pending_group, self.clone()))
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
            return Err(Error::ConversationAlreadyExists(id.to_owned()));
        }

        let credential = credential_ref.load(&*database).await.map_err(RecursiveError::context(
            "loading credential from database to create new conversation",
        ))?;

        let config = configuration
            .as_openmls_default_configuration()
            .map_err(RecursiveError::context("converting config to openmls default"))?;

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
