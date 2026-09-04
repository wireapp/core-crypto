use openmls::{group::MlsGroup, prelude::Welcome};

use crate::{
    ConversationConfiguration, ConversationId, LeafError, OpenMlsError, RecursiveError,
    mls::{
        TntMessageCounter,
        conversation::{Conversation, ConversationMut, Error as ConversationError, MlsGroupState},
    },
    transaction_context::{Result, TransactionContext},
};

impl TransactionContext {
    /// Create a conversation from an existing MLS group.
    ///
    /// For example, by external commit.
    ///
    /// This effectively goes through the following steps:
    ///
    /// 1. Produce a [`Conversation`] from the group.
    /// 2. Persist that conversation in the database.
    /// 3. Persist that conversation in the conversation cache.
    /// 4. Return the cached entry for that conversation.
    ///
    /// Note that this does not check whether or not the conversation already exists.
    pub(crate) async fn persist_conversation_from_mls_group(
        &self,
        group: MlsGroup,
        configuration: ConversationConfiguration,
        tnt_message_counter: TntMessageCounter,
    ) -> Result<ConversationMut> {
        let id = ConversationId::from(group.group_id().as_slice());
        let mut group_state = MlsGroupState::new(group, tnt_message_counter);

        let context_inner = self.inner().await?;
        group_state
            .persist(&context_inner.transaction)
            .await
            .map_err(RecursiveError::mls_conversation("persisting group state for new group"))?;

        // now that we're persisted, construct a conversation
        let session = self.session().await.map_err(RecursiveError::transaction(
            "getting session from tx context to persist",
        ))?;
        let conversation = Conversation::new(id, group_state.into(), configuration, session);
        let mut group_store = self.mls_groups().await?;

        let inner = group_store.insert(conversation);
        Ok(ConversationMut::new(inner, self.clone()))
    }

    /// Create a MLS conversation from an MLS Welcome message
    ///
    /// Unlike [`Self::persist_conversation_from_mls_group`], this _does_ check whether the conversation
    /// already exists or is pending. If it does, returns [`LeafError::ConversationAlreadyExists`].
    pub(crate) async fn persist_conversation_from_welcome_message(
        &self,
        welcome: Welcome,
        configuration: ConversationConfiguration,
    ) -> Result<ConversationMut> {
        let mls_group_config =
            configuration
                .as_openmls_default_configuration()
                .map_err(RecursiveError::mls_conversation(
                    "converting configuration to openmls default",
                ))?;

        let crypto_provider = self.crypto_provider().await?;

        let group = MlsGroup::new_from_welcome(&crypto_provider, &mls_group_config, welcome, None)
            .await
            .map_err(|err| {
                use openmls::prelude::WelcomeError;
                if matches!(
                    err,
                    WelcomeError::NoMatchingKeyPackage | WelcomeError::NoMatchingEncryptionKey
                ) {
                    ConversationError::OrphanWelcome
                } else {
                    OpenMlsError::wrap("group could not be created from welcome")(err).into()
                }
            })
            .map_err(RecursiveError::mls_conversation(
                "creating mls group from welcome message",
            ))?;

        let id = ConversationId::from(group.group_id().as_slice());

        if self.conversation_exists(&id).await? || self.pending_conversation_exists(&id).await? {
            return Err(LeafError::ConversationAlreadyExists(id).into());
        }

        self.persist_conversation_from_mls_group(group, configuration, Default::default())
            .await
    }
}
