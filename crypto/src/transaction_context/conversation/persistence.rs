use core_crypto_keystore::{
    entities::{PersistedMlsGroup, StoredCredentialPk},
    traits::EntityDatabaseMutation as _,
};
use openmls::{
    group::{MlsGroup, ProcessedWelcome},
    prelude::Welcome,
};

use crate::{
    ConversationConfiguration, ConversationId, KeystoreError, OpenMlsError, PendingStatus, RecursiveError,
    mls::{
        conversation::{Conversation, ConversationIdRef, ConversationMut, Error as ConversationError, MlsGroupState},
        credential::validation::validate_credentials,
    },
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
    /// 2. Persist that conversation in the database. The group's row must already exist; see
    ///    [`Self::insert_group_row`].
    /// 3. Persist that conversation in the conversation cache.
    /// 4. Return the cached entry for that conversation.
    ///
    /// Note that this does not check whether or not the conversation already exists.
    pub(crate) async fn persist_conversation_from_mls_group(
        &self,
        group: MlsGroup,
        configuration: ConversationConfiguration,
        pending_status: PendingStatus,
    ) -> Result<ConversationMut> {
        let id = ConversationId::from(group.group_id().as_slice());
        let group_state = MlsGroupState::new(group, Default::default(), pending_status);

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
        let conversation = Conversation::new(id, group_state.into(), configuration.into(), session);
        let mut group_store = self.mls_groups().await?;

        context_inner.conversation_touched(conversation.id()).await;
        let inner = group_store.insert(conversation);
        let conversation = ConversationMut::new(inner, self.clone());

        if pending_status == PendingStatus::Operational {
            // this place is a convergence point where every path to a new group gets saved,
            // so we can use it for the initial epoch data recording
            // (the call path in `mutate_group` only ever handle subsequent epochs, not the initial)
            conversation
                .record_initial_epoch_data()
                .await
                .map_err(RecursiveError::context(
                    "recording initial epoch data when persisting from mls group",
                ))?;
        }

        Ok(conversation)
    }

    /// Insert the row of a group we're about to create or join.
    ///
    /// openmls writes the group's state into this row as it builds the group, and those writes fail if the row isn't
    /// there yet. So this has to happen first. `epoch`, `ciphersuite` and `own_leaf_index` start out as zero: every
    /// way openmls builds a group stores it, which writes all three.
    ///
    /// If the group already has a row, this overwrites core-crypto's columns and leaves openmls's state alone.
    pub(crate) fn insert_group_row(
        &self,
        id: &ConversationIdRef,
        credential: &StoredCredentialPk,
        pending_status: PendingStatus,
    ) -> Result<()> {
        PersistedMlsGroup {
            id: id.as_ref().into(),
            epoch: 0,
            ciphersuite: 0,
            credential_id: credential.public_key_hash,
            credential_type: credential.credential_type,
            credential_not_before: credential.not_before,
            own_leaf_index: 0,
            is_pending: pending_status.is_pending(),
            tnt_tx_counter: 0,
        }
        .save(self.inner()?.transaction())
        .map_err(KeystoreError::wrap("inserting the row of a new mls group"))?;
        Ok(())
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
        let join_config = configuration.as_openmls_join_config();
        let crypto_provider = self.mls_provider().await?;
        let inner = self.inner()?;
        let provider = crypto_provider.with_transaction(inner.transaction());

        let processed_welcome = ProcessedWelcome::new_from_welcome(&provider, &join_config, welcome)
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

        // openmls refuses to stage a welcome to a group it already has, without telling us which group. So we check
        // first, with the group id from the welcome's group info. That isn't verified yet, but staging only goes ahead
        // for the group this names.
        let id = ConversationId::from(processed_welcome.unverified_group_info().group_id().as_slice());
        if self.conversation_exists(&id, None).await? {
            return Err(Error::ConversationAlreadyExists(id));
        }

        let staged_welcome = processed_welcome
            .into_staged_welcome(&provider, None)
            .map_err(OpenMlsError::wrap("staging the welcome"))
            .map_err(ConversationError::from)
            .map_err(RecursiveError::context("creating mls group from welcome message"))?;

        validate_credentials(
            crypto_provider.authentication_service(),
            &staged_welcome
                .members()
                .map(|member| member.credential)
                .collect::<Vec<_>>(),
        )
        .await
        .map_err(RecursiveError::mls_credential(
            "checking the credentials of the group we're welcomed to",
        ))?;

        let own_leaf = staged_welcome
            .own_leaf_node()
            .ok_or(ConversationError::MlsGroupInvalidState(
                "the group we were welcomed to has no leaf of ours",
            ))
            .map_err(RecursiveError::context("finding our own leaf in the welcome"))?;
        let credential =
            StoredCredentialPk::from_mls_credential(own_leaf.signature_key().as_slice(), own_leaf.credential())
                .map_err(KeystoreError::wrap("computing the primary key of our credential"))?;

        // Joining writes the group's row and its state. Bundle them, so a failed join leaves neither behind even if
        // the caller carries on with this transaction.
        inner
            .with_savepoint(
                "join_by_welcome",
                async || {
                    self.insert_group_row(&id, &credential, PendingStatus::Operational)?;
                    let group = staged_welcome
                        .into_group(&provider)
                        .map_err(OpenMlsError::wrap("joining group from staged welcome"))?;
                    self.persist_conversation_from_mls_group(group, configuration, PendingStatus::Operational)
                        .await
                },
                Error::savepoint,
            )
            .await
    }
}
