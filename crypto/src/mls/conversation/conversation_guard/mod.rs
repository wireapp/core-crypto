mod commit;
mod commit_delay;
pub(crate) mod decrypt;
mod encrypt;
mod group_mutation;
mod history_sharing;
mod merge;
mod own_commit;
mod proposal;
mod wipe;

use std::sync::Arc;

use async_lock::{RwLock, RwLockReadGuard, RwLockReadGuardArc};
use core_crypto_keystore::Database;
use openmls::prelude::group_info::GroupInfo;

use super::{ConversationWithMls, Error, MlsConversation, Result};
use crate::{
    LeafError, MlsCryptoProvider, MlsGroupInfoBundle, MlsTransport, RecursiveError,
    mls::{HasSessionAndCrypto, conversation::ImmutableConversation, credential::Credential},
    transaction_context::TransactionContext,
};

/// A Conversation Guard wraps an [`Arc<RwLock<MlsConversation>>`].
///
/// The conversation is ultimately owned by the [conversation cache][crate::mls::conversation_cache::MlsConversationCache], but we take an `Arc`
/// here so that we don't have to tie the lifetime of the guard to the cache.
///
/// More generally, the conversation guard gives us convenient mutable accesses to a single
/// conversation. This in turn means that we don't have to duplicate the entire
/// `MlsConversation` API on `TransactionContext`.
#[derive(Debug)]
pub struct ConversationGuard {
    inner: Arc<RwLock<ImmutableConversation>>,
    tx_context: TransactionContext,
}

#[cfg_attr(target_os = "unknown", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_os = "unknown"), async_trait::async_trait)]
impl<'inner> ConversationWithMls<'inner> for ConversationGuard {
    type Context = TransactionContext;
    type Conversation = RwLockReadGuard<'inner, MlsConversation>;

    async fn context(&self) -> Result<TransactionContext> {
        Ok(self.tx_context.clone())
    }

    async fn conversation(&'inner self) -> RwLockReadGuard<'inner, MlsConversation> {
        unimplemented!("we will remove this trait shortly")
    }
}

impl ConversationGuard {
    pub(crate) fn new(inner: Arc<RwLock<ImmutableConversation>>, tx_context: TransactionContext) -> Self {
        Self { inner, tx_context }
    }

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
            .map_err(RecursiveError::mls(
                "acquiring crypto provider for conversation guard from tx context",
            ))
            .map_err(Into::into)
    }

    /// Get access to the inner, immutable conversation
    async fn inner(&self) -> RwLockReadGuardArc<ImmutableConversation> {
        self.inner.read_arc().await
    }

    pub(crate) async fn credential(&self) -> Result<Arc<Credential>> {
        self.inner()
            .await
            .find_current_credential()
            .await
            .map_err(|_| Error::IdentityInitializationError)
    }

    fn group_info(group_info: Option<GroupInfo>) -> Result<MlsGroupInfoBundle> {
        let group_info = group_info.ok_or(LeafError::MissingGroupInfo)?;
        MlsGroupInfoBundle::try_new_full_plaintext(group_info)
    }
}

#[cfg(test)]
mod test_utils {
    use super::ConversationGuard;
    use crate::mls::conversation::ImmutableConversation;

    impl ConversationGuard {
        /// Replaces the MLS group in memory with the one from keystore.
        pub async fn drop_and_restore(&mut self) {
            let session = self.tx_context.session().await.unwrap();
            let inner = self.inner().await;
            let id = inner.id();

            let conversation = ImmutableConversation::load(session, id).await.unwrap().unwrap();
            self.tx_context.mls_groups().await.unwrap().insert(conversation);
        }
    }
}
