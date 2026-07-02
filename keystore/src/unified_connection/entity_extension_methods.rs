//! The methods defined in this module are extensions designed to improve entity ergonomics.

use crate::{
    CryptoKeystoreError, CryptoKeystoreResult, Database,
    entities::{MlsPendingMessage, PersistedMlsGroup},
    traits::UnifiedSearchableEntity as _,
};

// These and all other database impls shold not refer directly to `self.conn` but should go through the `self.conn()`
// wrapper
impl Database {
    pub async fn child_groups(&self, entity: PersistedMlsGroup) -> CryptoKeystoreResult<Vec<PersistedMlsGroup>> {
        let conn = self.conn().await;
        let persisted_records = entity.child_groups(&conn).await?;

        let transaction_guard = self.transaction.lock().await;
        let Some(transaction) = transaction_guard.as_ref() else {
            return Ok(persisted_records);
        };
        transaction.child_groups(entity, persisted_records).await
    }

    pub async fn find_pending_messages_by_conversation_id(
        &self,
        conversation_id: &[u8],
    ) -> CryptoKeystoreResult<Vec<MlsPendingMessage>> {
        let conn = self.conn().await;
        let persisted_records = MlsPendingMessage::find_all_matching(&conn, &conversation_id.into())?;

        let transaction_guard = self.transaction.lock().await;
        let Some(transaction) = transaction_guard.as_ref() else {
            return Ok(persisted_records);
        };
        transaction
            .find_pending_messages_by_conversation_id(conversation_id, persisted_records)
            .await
    }

    pub async fn remove_pending_messages_by_conversation_id(
        &self,
        conversation_id: impl AsRef<[u8]> + Send,
    ) -> CryptoKeystoreResult<()> {
        let transaction_guard = self.transaction.lock().await;
        let Some(transaction) = transaction_guard.as_ref() else {
            return Err(CryptoKeystoreError::MutatingOperationWithoutTransaction);
        };
        transaction
            .remove_pending_messages_by_conversation_id(conversation_id)
            .await;
        Ok(())
    }
}
