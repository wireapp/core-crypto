//! This module contains all [super::TransactionContext] methods related to a conversation.

pub mod external_commit;
mod external_proposal;
pub(crate) mod proposal;
pub mod welcome;

use std::sync::Arc;

use async_lock::{RwLock, RwLockUpgradableReadGuard};
use core_crypto_keystore::{entities::PersistedMlsPendingGroup, traits::FetchFromDatabase as _};

use super::{Error, Result, TransactionContext};
use crate::{
    CredentialRef, KeystoreError, LeafError, MlsConversation, MlsConversationConfiguration, RecursiveError,
    mls::conversation::{ConversationGuard, ConversationIdRef, pending_conversation::PendingConversation},
};

impl TransactionContext {
    /// Acquire a conversation guard.
    ///
    /// This helper struct permits mutations on a conversation.
    pub async fn conversation(&self, id: &ConversationIdRef) -> Result<ConversationGuard> {
        let database = self.database().await?;
        let conversation_cache = self.conversation_cache().await?;
        let conversation_cache = conversation_cache.upgradable_read().await;

        let maybe_conversation = if let Some(conversation_from_cache) = conversation_cache.get(id) {
            Some(conversation_from_cache.clone())
        } else {
            let conversation_from_db = MlsConversation::load(&database, id)
                .await
                .map_err(RecursiveError::mls_conversation("loading conversation from database"))?
                .map(RwLock::new)
                .map(Arc::new);
            if let Some(conversation) = &conversation_from_db {
                let mut conversation_cache = RwLockUpgradableReadGuard::upgrade(conversation_cache).await;
                conversation_cache.insert(id.to_owned(), conversation.clone());
            }
            conversation_from_db
        };

        if let Some(conversation) = maybe_conversation {
            return Ok(ConversationGuard::new(conversation, self.clone()));
        }

        // Check if there is a pending conversation with
        // the same id
        let pending = self.pending_conversation(id).await.map(Error::PendingConversation)?;
        Err(pending)
    }

    pub(crate) async fn pending_conversation(&self, id: &ConversationIdRef) -> Result<PendingConversation> {
        let keystore = self.database().await?;
        let Some(pending_group) = keystore
            .get_borrowed::<PersistedMlsPendingGroup>(id.as_ref())
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
        config: MlsConversationConfiguration,
    ) -> Result<()> {
        let database = &self.database().await?;
        let provider = &self.mls_provider().await?;
        if self.conversation_exists(id).await? || self.pending_conversation_exists(id).await? {
            return Err(LeafError::ConversationAlreadyExists(id.to_owned()).into());
        }
        let _ = MlsConversation::create(id.to_owned(), provider, database, credential_ref, config)
            .await
            .map_err(RecursiveError::mls_conversation("creating conversation"))?;

        Ok(())
    }

    /// Checks if a given conversation id exists locally
    pub async fn conversation_exists(&self, id: &ConversationIdRef) -> Result<bool> {
        let database = &self.database().await?;
        MlsConversation::load(database, id)
            .await
            .map(|option| option.is_some())
            .map_err(RecursiveError::mls_conversation("loading conversation from database"))
            .map_err(Into::into)
    }
}
