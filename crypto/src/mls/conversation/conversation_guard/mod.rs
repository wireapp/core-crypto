mod commit;
mod encrypt;

use async_lock::{RwLockReadGuard, RwLockWriteGuard};
use mls_crypto_provider::MlsCryptoProvider;
use openmls::prelude::group_info::GroupInfo;

use crate::{
    context::CentralContext,
    group_store::GroupStoreValue,
    prelude::{Client, MlsGroupInfoBundle},
    LeafError, RecursiveError,
};

use super::{commit::MlsCommitBundle, Error, MlsConversation, Result};

/// A Conversation Guard wraps a `GroupStoreValue<MlsConversation>`.
///
/// By doing so, it permits mutable accesses to the conversation. This in turn
/// means that we don't have to duplicate the entire `MlsConversation` API
/// on `CentralContext`.
pub struct ConversationGuard {
    inner: GroupStoreValue<MlsConversation>,
    central_context: CentralContext,
}

impl ConversationGuard {
    pub(crate) fn new(inner: GroupStoreValue<MlsConversation>, central_context: CentralContext) -> Self {
        Self { inner, central_context }
    }

    // This is dead code for now but we expect it to come alive in near-future work.
    #[expect(dead_code)]
    pub(crate) async fn conversation(&self) -> RwLockReadGuard<MlsConversation> {
        self.inner.read().await
    }

    pub(crate) async fn conversation_mut(&mut self) -> RwLockWriteGuard<MlsConversation> {
        self.inner.write().await
    }

    async fn mls_client(&self) -> Result<Client> {
        self.central_context
            .mls_client()
            .await
            .map_err(RecursiveError::root("getting mls client"))
            .map_err(Into::into)
    }

    async fn mls_provider(&self) -> Result<MlsCryptoProvider> {
        self.central_context
            .mls_provider()
            .await
            .map_err(RecursiveError::root("getting mls provider"))
            .map_err(Into::into)
    }

    pub(crate) async fn send_and_merge_commit(&mut self, commit: MlsCommitBundle) -> Result<()> {
        // note we hand over this instance of the guard; when we need a `conversation` guard again,
        // we'll need to re-fetch it.
        let conversation = self.inner.write().await;
        match self.central_context.send_commit(commit, Some(conversation)).await {
            Ok(false) => Ok(()),
            Ok(true) => {
                let backend = self.mls_provider().await?;
                let mut conversation = self.inner.write().await;
                conversation.commit_accepted(&backend).await
            }
            Err(e @ Error::MessageRejected { .. }) => {
                let backend = self.mls_provider().await?;
                let mut conversation = self.inner.write().await;
                conversation.clear_pending_commit(&backend).await?;
                Err(e)
            }
            Err(e) => Err(e),
        }
    }

    fn group_info(group_info: Option<GroupInfo>) -> Result<MlsGroupInfoBundle> {
        let group_info = group_info.ok_or(LeafError::MissingGroupInfo)?;
        MlsGroupInfoBundle::try_new_full_plaintext(group_info)
    }
}
