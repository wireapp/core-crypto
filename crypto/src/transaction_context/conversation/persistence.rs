use core_crypto_keystore::CryptoKeystoreMls as _;
use openmls::{
    group::{InnerState, MlsGroup},
    prelude::Welcome,
};

use crate::{
    ConversationId, KeystoreError, LeafError, MlsConversationConfiguration, MlsError, RecursiveError,
    mls::conversation::{ConversationMut, Error as ConversationError, ImmutableConversation},
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
    ///
    /// Note that this does not check whether or not the conversation already exists.
    pub(crate) async fn persist_conversation_from_mls_group(
        &self,
        mut group: MlsGroup,
        configuration: MlsConversationConfiguration,
    ) -> Result<ConversationMut> {
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
        let conversation = ImmutableConversation::new(id, group.into(), configuration, session);
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
        configuration: MlsConversationConfiguration,
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
                    MlsError::wrap("group could not be created from welcome")(err).into()
                }
            })
            .map_err(RecursiveError::mls_conversation(
                "creating mls group from welcome message",
            ))?;

        let id = ConversationId::from(group.group_id().as_slice());

        if self.conversation_exists(&id).await? || self.pending_conversation_exists(&id).await? {
            return Err(LeafError::ConversationAlreadyExists(id).into());
        }

        self.persist_conversation_from_mls_group(group, configuration).await
    }
}
