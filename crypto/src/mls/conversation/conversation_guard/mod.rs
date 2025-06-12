use std::sync::Arc;

use async_lock::{RwLockReadGuard, RwLockWriteGuard};
use core_crypto_keystore::CryptoKeystoreMls as _;
use openmls::prelude::group_info::GroupInfo;
use openmls_traits::OpenMlsCryptoProvider as _;

use super::{ConversationWithMls, Error, MlsConversation, Result};
use crate::MlsTransport;
use crate::mls::credential::CredentialBundle;
use crate::prelude::ConversationId;
use crate::{
    KeystoreError, LeafError, RecursiveError, group_store::GroupStoreValue, prelude::MlsGroupInfoBundle,
    transaction_context::TransactionContext,
};
mod commit;
pub(crate) mod decrypt;
mod encrypt;
mod merge;

/// A Conversation Guard wraps a `GroupStoreValue<MlsConversation>`.
///
/// By doing so, it permits mutable accesses to the conversation. This in turn
/// means that we don't have to duplicate the entire `MlsConversation` API
/// on `TransactionContext`.
#[derive(Debug)]
pub struct ConversationGuard {
    inner: GroupStoreValue<MlsConversation>,
    central_context: TransactionContext,
}

#[cfg_attr(target_family = "wasm", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_family = "wasm"), async_trait::async_trait)]
impl<'inner> ConversationWithMls<'inner> for ConversationGuard {
    type Context = TransactionContext;
    type Conversation = RwLockReadGuard<'inner, MlsConversation>;

    async fn context(&self) -> Result<TransactionContext> {
        Ok(self.central_context.clone())
    }

    async fn conversation(&'inner self) -> RwLockReadGuard<'inner, MlsConversation> {
        self.inner.read().await
    }
}

impl ConversationGuard {
    pub(crate) fn new(inner: GroupStoreValue<MlsConversation>, central_context: TransactionContext) -> Self {
        Self { inner, central_context }
    }

    pub(crate) async fn conversation_mut(&mut self) -> RwLockWriteGuard<MlsConversation> {
        self.inner.write().await
    }

    async fn transport(&self) -> Result<Arc<dyn MlsTransport>> {
        let transport = self
            .session()
            .await?
            .transport
            .read()
            .await
            .as_ref()
            .ok_or::<Error>(
                RecursiveError::root("getting mls transport")(crate::Error::MlsTransportNotProvided).into(),
            )?
            .clone();
        Ok(transport)
    }

    /// Destroys a group locally
    ///
    /// # Errors
    /// KeyStore errors, such as IO
    pub async fn wipe(&mut self) -> Result<()> {
        let provider = self.crypto_provider().await?;
        let mut group_store = self
            .central_context
            .mls_groups()
            .await
            .map_err(RecursiveError::transaction("getting mls groups"))?;
        let mut conversation = self.conversation_mut().await;
        conversation.wipe_associated_entities(&provider).await?;
        provider
            .key_store()
            .mls_group_delete(conversation.id())
            .await
            .map_err(KeystoreError::wrap("deleting mls group"))?;
        let _ = group_store.remove(conversation.id());
        Ok(())
    }

    /// This is not used right now, just like the entire mechanism of parent and
    /// child conversations. When our threat model requires it, we can re-enable this, or we remove
    /// it, along with all other code related to parent-child conversations.
    #[expect(dead_code)]
    pub(crate) async fn get_parent(&self) -> Result<Option<Self>> {
        let conversation_lock = self.conversation().await;
        let Some(parent_id) = conversation_lock.parent_id.as_ref() else {
            return Ok(None);
        };
        self.central_context
            .conversation(parent_id)
            .await
            .map(Some)
            .map_err(|_| Error::ParentGroupNotFound)
    }

    /// Marks this conversation as child of another.
    /// Prerequisite: Must be a member of the parent group, and it must exist in the keystore
    pub async fn mark_as_child_of(&mut self, parent_id: &ConversationId) -> Result<()> {
        let backend = self.crypto_provider().await?;
        let keystore = &backend.keystore();
        let mut conversation = self.conversation_mut().await;
        if keystore.mls_group_exists(parent_id).await {
            conversation.parent_id = Some(parent_id.clone());
            conversation.persist_group_when_changed(keystore, true).await?;
            Ok(())
        } else {
            Err(Error::ParentGroupNotFound)
        }
    }

    async fn credential_bundle(&self) -> Result<Arc<CredentialBundle>> {
        let client = self.session().await?;
        let inner = self.conversation().await;
        inner
            .find_current_credential_bundle(&client)
            .await
            .map_err(|_| Error::IdentityInitializationError)
    }

    fn group_info(group_info: Option<GroupInfo>) -> Result<MlsGroupInfoBundle> {
        let group_info = group_info.ok_or(LeafError::MissingGroupInfo)?;
        MlsGroupInfoBundle::try_new_full_plaintext(group_info)
    }
}

#[cfg(test)]
pub mod test_utils {
    use super::ConversationGuard;
    use crate::{mls::conversation::ConversationWithMls as _, prelude::MlsConversation};

    impl ConversationGuard {
        /// Replaces the MLS group in memory with the one from keystore.
        pub async fn drop_and_restore(&mut self) {
            use core_crypto_keystore::CryptoKeystoreMls as _;
            let context = self.context().await.unwrap();
            let inner = self.conversation().await;
            let id = inner.id();

            let (parent_id, group) = context
                .keystore()
                .await
                .unwrap()
                .mls_groups_restore()
                .await
                .map(|mut groups| groups.remove(id.as_slice()).unwrap())
                .unwrap();
            let group = MlsConversation::from_serialized_state(group, parent_id).unwrap();
            context.mls_groups().await.unwrap().insert(id.clone(), group);
        }
    }
}
