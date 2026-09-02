use core_crypto_keystore::{
    Transaction,
    ancillary::ConversationEpochsOlderThan,
    entities::{TargetedMessageRxCounter, TntSecret, TntSecretPkRef, TransientMessageRxCounter},
    traits::{DeletableBySearchKey as _, EntityDatabaseMutation as _, FetchFromDatabase as _},
};
use openmls::group::InnerState;

use super::{ConversationMut, Result};
use crate::{
    KeystoreError, RecursiveError,
    mls::conversation::{Conversation, ConversationIdRef, MlsGroupState, config::MAX_PAST_EPOCHS},
};

impl ConversationMut {
    /// Perform an operation on a mutable reference to the contained MLS group.
    ///
    /// Errors will be propagated.
    /// When the operation does not error, the group will automatically be persisted.
    /// This ensures that persistence cannot be forgotten.
    ///
    /// We choose to implement this as a closure instead of a lightweight holding a reference to the coversation
    /// which calls that method on `Drop` because this way we can ensure we do _not_ automatically call it when there is
    /// an error.
    ///
    /// ## Note
    ///
    /// This function requires acquiring a write lock on the immutable conversation; it will deadlock
    /// if any lock already exists on that conversation.
    pub(super) async fn mutate_group<T>(
        &mut self,
        operation: impl AsyncFnOnce(&Transaction, &mut MlsGroupState, &ConversationIdRef) -> Result<T>,
    ) -> Result<T> {
        // we can't get the transaction if the transaction context has been invalidated,
        // and we want to have that error first before evaluating anything in the operation.
        let context_inner = self
            .tx_context
            .inner()
            .await
            .map_err(RecursiveError::context("getting inner from context to mutate group"))?;
        let tx = context_inner.transaction();

        let Conversation { group, id, .. } = &*self.inner;
        let mut group = group.write().await;
        let epoch_before_operation = group.epoch();

        // Save the tnt secret. We need to do this exactly once per epoch.
        let tnt_secret_key = TntSecretPkRef::new(id.as_ref().into(), epoch_before_operation.as_u64());
        if tx
            .get_borrowed::<TntSecret>(tnt_secret_key)
            .await
            .map_err(KeystoreError::wrap("finding tnt secret for current epoch"))?
            .is_none()
        {
            self.create_tnt_secret(group.mls_group())
                .await?
                .save(tx)
                .map_err(KeystoreError::wrap("persisting tnt secret for current epoch"))?;
        }

        let ok_result = operation(tx, &mut *group, id).await?;

        if group.state_changed() == InnerState::Persisted {
            return Ok(ok_result);
        }

        if epoch_before_operation < group.epoch() {
            group.reset_tnt_message_tx_counter(tx).await?;

            let oldest_retained_epoch = group.epoch().as_u64().saturating_sub(MAX_PAST_EPOCHS as u64);
            let stale_epochs = ConversationEpochsOlderThan::new(id.as_ref().into(), oldest_retained_epoch);
            TntSecret::delete_all_matching(tx, &stale_epochs)
                .map_err(KeystoreError::wrap("deleting tnt secrets on epoch change"))?;
            TargetedMessageRxCounter::delete_all_matching(tx, &stale_epochs).map_err(KeystoreError::wrap(
                "deleting targeted message rx counter on epoch change",
            ))?;
            TransientMessageRxCounter::delete_all_matching(tx, &stale_epochs).map_err(KeystoreError::wrap(
                "deleting transient message rx counter on epoch change",
            ))?;
        }

        group.persist(tx).await?;

        Ok(ok_result)
    }

    /// Exactly as [`Self::mutate_group`], but accessible from anywhere in core-crypto for testing.
    #[cfg(test)]
    pub(crate) async fn mutate_group_test<T>(
        &mut self,
        operation: impl AsyncFnOnce(&Transaction, &mut MlsGroupState, &ConversationIdRef) -> Result<T>,
    ) -> Result<T> {
        self.mutate_group(operation).await
    }
}
