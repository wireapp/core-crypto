use core_crypto_keystore::{
    ancillary::ConversationEpochsNewerThan, entities::OldEpochData, traits::DeletableBySearchKey as _,
};
use openmls::{group::MlsGroup, prelude::Welcome};

use crate::{
    ConversationConfiguration, ConversationId, KeystoreError, OpenMlsError, RecursiveError,
    mls::conversation::{Conversation, ConversationMut, Error as ConversationError, MlsGroupState},
    transaction_context::{Error, Result, TransactionContext},
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
    ) -> Result<ConversationMut> {
        let id = ConversationId::from(group.group_id().as_slice());
        let mut group_state = MlsGroupState::new(group, Default::default());

        let context_inner = self.inner()?;
        group_state
            .persist(&context_inner.transaction)
            .await
            .map_err(RecursiveError::context("persisting group state for new group"))?;

        // now that we're persisted, construct a conversation
        let session = self
            .session()
            .await
            .map_err(RecursiveError::context("getting session from tx context to persist"))?;
        let session = std::sync::Arc::downgrade(&session);
        let conversation = Conversation::new(id, group_state.into(), configuration, session);
        let mut group_store = self.mls_groups().await?;

        context_inner.conversation_touched(conversation.id()).await;
        let inner = group_store.insert(conversation);
        let conversation = ConversationMut::new(inner, self.clone());

        // this place is a convergence point where every path to a new group gets saved,
        // so we can use it for the initial epoch data recording
        // (the call path in `mutate_group` only ever handle subsequent epochs, not the initial)
        {
            // we've just created the group, so if there exists any existing state at or after the
            // group's epoch, that history must be replaced.
            OldEpochData::delete_all_matching(
                self.inner()?.transaction(),
                &ConversationEpochsNewerThan::new(conversation.id().keystore(), conversation.epoch().await),
            )
            .map_err(KeystoreError::wrap("deleting any epoch data from a potential fork"))?;

            let group_state = conversation.group().await;
            conversation
                .record_epoch_data(group_state.mls_group())
                .await
                .map_err(RecursiveError::context(
                    "recording epoch data for new conversation creation",
                ))?;
        }

        Ok(conversation)
    }

    /// Create an MLS conversation from an MLS Welcome message
    ///
    /// Unlike [`Self::persist_conversation_from_mls_group`], this _does_ check whether the conversation
    /// already exists or is pending. If it does, returns [`Error::ConversationAlreadyExists`].
    pub(crate) async fn persist_conversation_from_welcome_message(
        &self,
        welcome: Welcome,
        configuration: ConversationConfiguration,
    ) -> Result<ConversationMut> {
        let mls_group_config = configuration
            .as_openmls_default_configuration()
            .map_err(RecursiveError::context("converting configuration to openmls default"))?;

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
            .map_err(RecursiveError::context("creating mls group from welcome message"))?;

        let id = ConversationId::from(group.group_id().as_slice());

        if self.conversation_exists(&id).await? || self.pending_conversation_exists(&id).await? {
            return Err(Error::ConversationAlreadyExists(id));
        }

        self.persist_conversation_from_mls_group(group, configuration).await
    }
}
