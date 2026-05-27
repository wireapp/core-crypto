use core_crypto_keystore::{CryptoKeystoreMls as _, Database};
use openmls::group::{InnerState, MlsGroup};

use super::{ConversationGuard, Result};
use crate::{
    KeystoreError, MlsConversationConfiguration, RecursiveError,
    mls::conversation::{ConversationIdRef, ImmutableConversation},
};

impl ConversationGuard {
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
        operation: impl AsyncFnOnce(
            &Database,
            &mut MlsGroup,
            &ConversationIdRef,
            &MlsConversationConfiguration,
        ) -> Result<T>,
    ) -> Result<T> {
        // we can't get the database if the transaction context has been invalidated,
        // and we want to have that error first before evaluating anything in the operation.
        let database = self
            .tx_context
            .database()
            .await
            .map_err(RecursiveError::transaction("getting database from context"))?;

        let ImmutableConversation {
            group,
            id,
            configuration,
            ..
        } = &*self.inner;
        let mut group = group.write().await;
        let ok_result = operation(&database, &mut *group, id, configuration).await?;

        if group.state_changed() == InnerState::Changed {
            database
                .mls_group_persist(
                    id,
                    &core_crypto_keystore::ser(&*group).map_err(KeystoreError::wrap("serializing group state"))?,
                    None,
                )
                .await
                .map_err(KeystoreError::wrap("persisting mls group"))?;

            group.set_state(InnerState::Persisted);
        }
        Ok(ok_result)
    }

    /// Exactly as [`Self::mutate_group`], but accessible from anywhere in core-crypto for testing.
    #[cfg(test)]
    pub(crate) async fn mutate_group_test<T>(
        &mut self,
        operation: impl AsyncFnOnce(
            &Database,
            &mut MlsGroup,
            &ConversationIdRef,
            &MlsConversationConfiguration,
        ) -> Result<T>,
    ) -> Result<T> {
        self.mutate_group(operation).await
    }
}
