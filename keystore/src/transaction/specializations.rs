//! These methods are specialized for performing certain entity-specific queries.

use std::{borrow::Cow, collections::hash_map::Entry, sync::Arc};

use super::dynamic_dispatch::EntityId;
use crate::{
    CryptoKeystoreResult,
    entities::{MlsPendingMessage, PersistedMlsGroup},
    traits::{BorrowPrimaryKey, Entity, KeyType as _},
    transaction::KeystoreTransaction,
};

impl KeystoreTransaction {
    pub(crate) async fn child_groups(
        &self,
        entity: PersistedMlsGroup,
        persisted_records: impl IntoIterator<Item = PersistedMlsGroup>,
    ) -> CryptoKeystoreResult<Vec<PersistedMlsGroup>> {
        // First get all raw groups from the cache, then filter by their parent id
        let cached_records = self.find_all_in_cache::<PersistedMlsGroup>().await;
        let cached_records = cached_records
            .iter()
            .filter(|maybe_child| {
                maybe_child
                    .parent_id
                    .as_deref()
                    .map(|parent_id| parent_id == entity.borrow_primary_key().bytes().as_ref())
                    .unwrap_or_default()
            })
            .map(Arc::as_ref)
            .map(Cow::Borrowed);

        let persisted_records = persisted_records.into_iter().map(Cow::Owned);

        Ok(self.merge_records(cached_records, persisted_records).await)
    }

    pub(crate) async fn remove_pending_messages_by_conversation_id(&self, conversation_id: impl AsRef<[u8]> + Send) {
        let conversation_id = conversation_id.as_ref();

        let mut cache_guard = self.cache.write().await;
        if let Entry::Occupied(mut table) = cache_guard.entry(MlsPendingMessage::COLLECTION_NAME) {
            table.get_mut().retain(|_key, entity| {
                let pending_message = entity
                    .downcast::<MlsPendingMessage>()
                    .expect("table for MlsPendingMessage contains only that type");
                pending_message.foreign_id != conversation_id
            });
        }
        drop(cache_guard);

        let mut deleted_set = self.deleted.write().await;
        deleted_set.insert(
            EntityId::from_key::<MlsPendingMessage>(conversation_id.into())
                .expect("mls pending messages are proper entities which can be parsed"),
        );
    }

    pub(crate) async fn find_pending_messages_by_conversation_id(
        &self,
        conversation_id: &[u8],
        persisted_records: impl IntoIterator<Item = MlsPendingMessage>,
    ) -> CryptoKeystoreResult<Vec<MlsPendingMessage>> {
        let persisted_records = persisted_records.into_iter().map(Cow::Owned);

        let cached_records = self.find_all_in_cache::<MlsPendingMessage>().await;
        let cached_records = cached_records
            .iter()
            .filter(|pending_message| pending_message.foreign_id == conversation_id)
            .map(Arc::as_ref)
            .map(Cow::Borrowed);

        let merged_records = self.merge_records(cached_records, persisted_records).await;
        Ok(merged_records)
    }
}
