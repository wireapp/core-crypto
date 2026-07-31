use core_crypto_keystore::{Transaction, entities::PersistedMlsGroup};
use openmls::group::{InnerState, MlsGroup};

use super::{ConversationMut, Result};
use crate::{
    KeystoreError, RecursiveError,
    mls::conversation::{Conversation, ConversationIdRef},
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
        operation: impl AsyncFnOnce(&Transaction, &mut MlsGroup, &ConversationIdRef) -> Result<T>,
    ) -> Result<T> {
        // we can't get the transaction if the transaction context has been invalidated,
        // and we want to have that error first before evaluating anything in the operation.
        let context_inner = self.tx_context.inner().await.map_err(RecursiveError::transaction(
            "getting inner from context to mutate group",
        ))?;
        let tx = context_inner.transaction();

        let Conversation { group, id, .. } = &*self.inner;
        let mut group = group.write().await;
        let epoch_before_operation = group.epoch();
        let ok_result = operation(tx, &mut *group.mls_group_mut(), id).await?;

        if group.state_changed() == InnerState::Persisted {
            return Ok(ok_result);
        }

        if epoch_before_operation < group.epoch() {
            group.reset_sender_nonce();
        }

        tx.save(PersistedMlsGroup {
            id: id.to_bytes(),
            state: core_crypto_keystore::ser(group.mls_group())
                .map_err(KeystoreError::wrap("serializing group state"))?,
            parent_id: None,
            sender_nonce: group.sender_nonce(),
        })
        .await
        .map_err(KeystoreError::wrap("persisting mls group"))?;

        group.mls_group_mut().set_state(InnerState::Persisted);

        Ok(ok_result)
    }

    /// Exactly as [`Self::mutate_group`], but accessible from anywhere in core-crypto for testing.
    #[cfg(test)]
    pub(crate) async fn mutate_group_test<T>(
        &mut self,
        operation: impl AsyncFnOnce(&Transaction, &mut MlsGroup, &ConversationIdRef) -> Result<T>,
    ) -> Result<T> {
        self.mutate_group(operation).await
    }
}
