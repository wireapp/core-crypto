mod commit;
mod encrypt;
mod merge;

use async_lock::{RwLockReadGuard, RwLockWriteGuard};
use openmls::prelude::group_info::GroupInfo;
use std::sync::Arc;

use super::{ConversationWithMls, Error, MlsConversation, Result, commit::MlsCommitBundle};
use crate::mls::credential::CredentialBundle;
use crate::{LeafError, context::CentralContext, group_store::GroupStoreValue, prelude::MlsGroupInfoBundle};

/// A Conversation Guard wraps a `GroupStoreValue<MlsConversation>`.
///
/// By doing so, it permits mutable accesses to the conversation. This in turn
/// means that we don't have to duplicate the entire `MlsConversation` API
/// on `CentralContext`.
#[derive(Debug)]
pub struct ConversationGuard {
    inner: GroupStoreValue<MlsConversation>,
    central_context: CentralContext,
}

#[cfg_attr(target_family = "wasm", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_family = "wasm"), async_trait::async_trait)]
impl<'inner> ConversationWithMls<'inner> for ConversationGuard {
    type Central = CentralContext;
    type Conversation = RwLockReadGuard<'inner, MlsConversation>;

    async fn central(&self) -> Result<CentralContext> {
        Ok(self.central_context.clone())
    }

    async fn conversation(&'inner self) -> RwLockReadGuard<'inner, MlsConversation> {
        self.inner.read().await
    }
}

impl ConversationGuard {
    pub(crate) fn new(inner: GroupStoreValue<MlsConversation>, central_context: CentralContext) -> Self {
        Self { inner, central_context }
    }

    pub(crate) async fn conversation_mut(&mut self) -> RwLockWriteGuard<MlsConversation> {
        self.inner.write().await
    }

    async fn credential_bundle(&self) -> Result<Arc<CredentialBundle>> {
        let client = self.mls_client().await?;
        let inner = self.conversation().await;
        inner
            .find_current_credential_bundle(&client)
            .await
            .map_err(|_| Error::IdentityInitializationError)
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
                self.clear_pending_commit().await?;
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
