use core_crypto_keystore::CryptoKeystoreMls as _;
use openmls::group::{InnerState, MlsGroup};

use crate::{
    ConversationId, KeystoreError, MlsConversationConfiguration, RecursiveError,
    mls::conversation::{ConversationGuard, ImmutableConversation},
    transaction_context::{Result, TransactionContext},
};

impl TransactionContext {
    /// Create a conversation from an existing MLS group.
    ///
    /// For example, by external commit.
    ///
    /// This effectively goes through the following steps:
    ///
    /// 1. Produce an [`ImmutableConversation`] from the group.
    /// 2. Persist that conversation in the database.
    /// 3. Persist that conversation in the conversation cache.
    /// 4. Return the cached entry for that conversation.
    pub(crate) async fn persist_from_mls_group(
        &self,
        mut group: MlsGroup,
        configuration: MlsConversationConfiguration,
    ) -> Result<ConversationGuard> {
        let id = ConversationId::from(group.group_id().as_slice());
        let session = self.session().await.map_err(RecursiveError::transaction(
            "getting session from tx context to persist",
        ))?;

        // we're actually out of order from the docs, beause this leads to a better data flow
        let database = self.database().await?;
        let group_state = core_crypto_keystore::ser(&group).map_err(KeystoreError::wrap("serializing group state"))?;
        database
            .mls_group_persist(&id, &group_state, None)
            .await
            .map_err(KeystoreError::wrap("persisting mls group"))?;
        group.set_state(InnerState::Persisted);

        // now that we're persisted, construct a conversation
        let conversation = ImmutableConversation::new(id, group, configuration, session);
        let mut group_store = self.mls_groups().await?;

        let inner = group_store.insert(conversation);
        Ok(ConversationGuard::new(inner, self.clone()))
    }
}
