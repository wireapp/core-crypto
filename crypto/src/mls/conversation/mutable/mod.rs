mod commit;
pub(crate) mod decrypt;
mod encrypt;
mod group_mutation;
mod history_sharing;
mod merge;
mod own_commit;
mod proposal;
mod wipe;

use std::sync::Arc;

use core_crypto_keystore::Database;
use openmls::prelude::group_info::GroupInfo;

use super::{Error, Result};
use crate::{
    LeafError, MlsCryptoProvider, MlsGroupInfoBundle, MlsTransport, RecursiveError, Session,
    mls::{conversation::ImmutableConversation, credential::Credential},
    transaction_context::TransactionContext,
};

/// A mutable view of an MLS conversation.
///
/// The conversation is ultimately owned by the [conversation
/// cache][crate::mls::conversation_cache::MlsConversationCache], but we take an `Arc` here so that we don't have to tie
/// the lifetime of the guard to the cache.
///
/// More generally, the conversation guard gives us convenient mutable accesses to a single
/// conversation. This in turn means that we don't have to duplicate the entire
/// conversation API on `TransactionContext`.
#[derive(Debug, derive_more::Constructor)]
pub struct ConversationMut {
    inner: Arc<ImmutableConversation>,
    tx_context: TransactionContext,
}

impl ConversationMut {
    async fn transport(&self) -> Result<Arc<dyn MlsTransport>> {
        self.tx_context
            .mls_transport()
            .await
            .map_err(RecursiveError::transaction("getting transport for conversation guard"))
            .map_err(Into::into)
    }

    async fn database(&self) -> Result<Database> {
        self.tx_context
            .database()
            .await
            .map_err(RecursiveError::transaction("getting database from context"))
            .map_err(Into::into)
    }

    async fn crypto_provider(&self) -> Result<MlsCryptoProvider> {
        self.tx_context
            .crypto_provider()
            .await
            .map_err(RecursiveError::transaction(
                "acquiring crypto provider for conversation guard from tx context",
            ))
            .map_err(Into::into)
    }

    pub(crate) async fn credential(&self) -> Result<Arc<Credential>> {
        self.find_current_credential()
            .await
            .map_err(|_| Error::IdentityInitializationError)
    }

    /// Get access to the MLS session for this guard
    pub(super) async fn session(&self) -> Result<Session> {
        self.tx_context
            .session()
            .await
            .map_err(RecursiveError::transaction("getting session from transaction context"))
            .map_err(Into::into)
    }

    fn group_info(group_info: Option<GroupInfo>) -> Result<MlsGroupInfoBundle> {
        let group_info = group_info.ok_or(LeafError::MissingGroupInfo)?;
        MlsGroupInfoBundle::try_new_full_plaintext(group_info)
    }
}

impl std::ops::Deref for ConversationMut {
    type Target = ImmutableConversation;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

#[cfg(test)]
mod test_utils {
    use super::ConversationMut;
    use crate::mls::conversation::ImmutableConversation;

    impl ConversationMut {
        /// Replaces the MLS group in memory with the one from keystore.
        pub async fn drop_and_restore(&mut self) {
            let session = self.tx_context.session().await.unwrap();
            let id = self.id();

            let conversation = ImmutableConversation::load(session, id).await.unwrap().unwrap();
            self.tx_context.mls_groups().await.unwrap().insert(conversation);
        }
    }
}
