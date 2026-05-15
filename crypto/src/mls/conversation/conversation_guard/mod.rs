use std::sync::Arc;

use async_lock::{RwLock, RwLockReadGuard};
use core_crypto_keystore::{CryptoKeystoreMls as _, Database};
use openmls::prelude::group_info::GroupInfo;
use openmls_traits::OpenMlsCryptoProvider as _;

use super::{ConversationWithMls, Error, MlsConversation, Result};
use crate::{
    KeystoreError, LeafError, MlsGroupInfoBundle, MlsTransport, RecursiveError, mls::credential::Credential,
    transaction_context::TransactionContext,
};
mod commit;
pub(crate) mod decrypt;
mod encrypt;
mod history_sharing;
mod merge;

/// A Conversation Guard wraps an [`Arc<RwLock<MlsConversation>>`].
///
/// The conversation ultimately lives in the
/// [`crate::mls::conversation_cache::MlsConversationCache`], but taking a guard lets us
///  more conveniently perform mutating operations on a particular conversation.
///
/// By doing so, it permits mutable accesses to the conversation. This in turn
/// means that we don't have to duplicate the entire `MlsConversation` API
/// on `TransactionContext`.
#[derive(Debug)]
pub struct ConversationGuard {
    inner: Arc<RwLock<MlsConversation>>,
    central_context: TransactionContext,
}

#[cfg_attr(target_os = "unknown", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_os = "unknown"), async_trait::async_trait)]
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
    pub(crate) fn new(inner: Arc<RwLock<MlsConversation>>, central_context: TransactionContext) -> Self {
        Self { inner, central_context }
    }

    /// Perform an operation on a mutable reference to this conversation.
    ///
    /// Errors will be propagated.
    /// When the operation does not error, [`MlsConversation::persist_group_when_changed`] will be called automatically.
    /// This ensures that persistence cannot be forgotten.
    ///
    /// We choose to implement this as a closure instead of a lightweight holding a reference to the coversation
    /// which calls that method on `Drop` because this way we can ensure we do _not_ automatically call it when there is
    /// an error.
    pub(crate) async fn conversation_mut<T>(
        &mut self,
        operation: impl AsyncFnOnce(&mut MlsConversation) -> Result<T>,
    ) -> Result<T> {
        // we can't get the database if the transaction context has been invalidated,
        // and we want to have that error first before evaluating anything in the operation.
        let database = self
            .central_context
            .database()
            .await
            .map_err(RecursiveError::transaction("getting database from context"))?;
        let mut guard = self.inner.write().await;
        let ok_result = operation(&mut guard).await?;
        guard.persist_group_when_changed(&database, false).await?;
        Ok(ok_result)
    }

    async fn transport(&self) -> Result<Arc<dyn MlsTransport>> {
        let transport = self.session().await?.transport.clone();
        Ok(transport)
    }

    async fn database(&self) -> Result<Database> {
        self.central_context
            .database()
            .await
            .map_err(RecursiveError::transaction("getting database from context"))
            .map_err(Into::into)
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

        let id = self
            .conversation_mut(async |conversation| {
                conversation.wipe_associated_entities(&provider).await?;
                Ok(conversation.id().to_owned())
            })
            .await?;
        provider
            .key_store()
            .mls_group_delete(&id)
            .await
            .map_err(KeystoreError::wrap("deleting mls group"))?;
        let _ = group_store.remove(&id);

        Ok(())
    }

    pub(crate) async fn credential(&self) -> Result<Arc<Credential>> {
        let client = self.session().await?;
        let inner = self.conversation().await;
        inner
            .find_current_credential(&client)
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
    use crate::{MlsConversation, mls::conversation::ConversationWithMls as _};

    impl ConversationGuard {
        /// Replaces the MLS group in memory with the one from keystore.
        pub async fn drop_and_restore(&mut self) {
            use core_crypto_keystore::CryptoKeystoreMls as _;
            let context = self.context().await.unwrap();
            let inner = self.conversation().await;
            let id = inner.id();

            let (_parent_id, group) = context
                .database()
                .await
                .unwrap()
                .mls_groups_restore()
                .await
                .map(|mut groups| groups.remove(id.as_ref()).unwrap())
                .unwrap();
            let group = MlsConversation::from_serialized_state(group).unwrap();
            context.mls_groups().await.unwrap().insert(group);
        }
    }
}
