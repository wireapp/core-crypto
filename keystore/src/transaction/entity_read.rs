//! These methods allow for read-only operations on the entities in the transaction,
//! without considering the database itself.

use std::sync::Arc;

use super::dynamic_dispatch::EntityId;
use crate::{
    traits::{BorrowPrimaryKey, Entity, KeyType, SearchableEntity},
    transaction::{ReadOutcome, Transaction},
};

impl Transaction {
    /// Get an entity by its id.
    ///
    /// This produces a [`ReadOutcome`] which has information about whether the tx
    /// knows about an upsert or delete of that entity, and also a set of filters
    /// which can be used to exclude matching entities produced by the underlying DB.
    ///
    /// ## Caution
    ///
    /// This correctly filters out upserted entities which were later bulk-deleted.
    /// However, it _cannot_ indicate bulk deletions for entities which were not
    /// previously upserted in this transaction. Other composing methods which have
    /// context from the database have to perform their own bulk-deletion filtering!
    async fn get_by_entity_id<E>(&self, entity_id: &EntityId) -> ReadOutcome<E>
    where
        E: 'static + Entity + Send + Sync,
    {
        let operations = self.operations.read().await;

        let bulk_delete_filters = operations.bulk_delete_filters::<E>();
        let entity = operations.last_mutation_idx_for(entity_id).map(|entity_idx| {
            let mut stored_entity = operations[entity_idx].as_upsert::<E>();

            // run each filter coming after the stored entity against that entity
            if let Some(entity) = stored_entity.as_ref() {
                if bulk_delete_filters.applies_after(entity, entity_idx) {
                    stored_entity.take();
                }
            }

            stored_entity
        });
        let filters = bulk_delete_filters.into_inner();

        ReadOutcome { entity, filters }
    }

    /// Get an entity by its primary key.
    ///
    /// This produces a [`ReadOutcome`] which has information about whether the tx
    /// knows about an upsert or delete of that entity, and also a set of filters
    /// which can be used to exclude matching entities produced by the underlying DB.
    pub(crate) async fn get<E>(&self, id: &E::PrimaryKey) -> ReadOutcome<E>
    where
        E: 'static + Entity + Send + Sync,
    {
        let entity_id = EntityId::from_primary_key::<E>(id);
        self.get_by_entity_id(&entity_id).await
    }

    /// Get an entity by the borrowed form of its primary key.
    ///
    /// This produces a [`ReadOutcome`] which has information about whether the tx
    /// knows about an upsert or delete of that entity, and also a set of filters
    /// which can be used to exclude matching entities produced by the underlying DB.
    pub(crate) async fn get_borrowed<E>(&self, id: &E::BorrowedPrimaryKey) -> ReadOutcome<E>
    where
        E: 'static + Entity + BorrowPrimaryKey + Send + Sync,
    {
        let entity_id = EntityId::from_borrowed_primary_key::<E>(id);
        self.get_by_entity_id(&entity_id).await
    }

    /// Apply the transaction's operations in order, producing all entities of type `E`.
    ///
    /// ## Caution
    ///
    /// This correctly filters out upserted entities which were later bulk-deleted.
    /// However, it _cannot_ filter out bulk deletions for entities which were not
    /// previously upserted in this transaction. Other composing methods which have
    /// context from the database have to perform their own bulk-deletion filtering!
    pub(super) async fn find_all_in_cache<E>(&self) -> Vec<Arc<E>>
    where
        E: 'static + Entity + Send + Sync,
    {
        let operations = self.operations.read().await;

        let bulk_delete_filters = operations.bulk_delete_filters::<E>();
        operations
            .upsert_indices_for_type::<E>()
            .filter_map(|(entity_id, idx)| {
                if operations
                    .last_delete_idx_for(&entity_id)
                    .is_some_and(|delete_idx| delete_idx > idx)
                {
                    // entity was deleted individually
                    return None;
                }

                let entity = operations[idx]
                    .as_upsert::<E>()
                    .expect("upsert_indices_for_type contains correct indices");

                if bulk_delete_filters.applies_after(&entity, idx) {
                    // entity was bulk-deleted
                    return None;
                }

                Some(entity)
            })
            .collect::<Vec<_>>()
    }

    /// Apply the transaction's operations in order, producing all entities of type `E`
    /// which match the provided search key.
    ///
    /// ## Caution
    ///
    /// This correctly filters out upserted entities which were later bulk-deleted.
    /// However, it _cannot_ filter out bulk deletions for entities which were not
    /// previously upserted in this transaction. Other composing methods which have
    /// context from the database have to perform their own bulk-deletion filtering!
    async fn search_in_cache<E, SearchKey>(&self, search_key: &SearchKey) -> impl Iterator<Item = Arc<E>>
    where
        E: 'static + Entity + SearchableEntity<SearchKey> + Send + Sync,
        SearchKey: KeyType,
    {
        self.find_all_in_cache::<E>()
            .await
            .into_iter()
            .filter(|entity| entity.matches(search_key))
    }

    /// Find all the entities of type `E` in the database as modified by the operations in this transaction.
    pub(crate) async fn find_all<E>(&self, persisted_records: impl IntoIterator<Item = E>) -> impl Iterator<Item = E>
    where
        E: 'static + Clone + Entity + Send + Sync,
    {
        let cached_records = self.find_all_in_cache::<E>().await;
        self.merge_records(cached_records.into_iter().map(Arc::unwrap_or_clone), persisted_records)
            .await
    }

    /// Find all the entities of type `E` in the database which match `search_key`,
    /// as modified by the operations in this transaction.
    pub(crate) async fn search<E, SearchKey>(
        &self,
        persisted_records: impl IntoIterator<Item = E>,
        search_key: &SearchKey,
    ) -> impl Iterator<Item = E>
    where
        E: 'static + Clone + Entity + SearchableEntity<SearchKey> + Send + Sync,
        SearchKey: KeyType,
    {
        let cached_records = self.search_in_cache(search_key).await;
        self.merge_records(cached_records.map(Arc::unwrap_or_clone), persisted_records)
            .await
    }
}

/// These tests pin down the contract documented on [`Transaction::get_by_entity_id`]: an upsert
/// covered by a later bulk deletion must read as deleted, and a bulk deletion alone must not.
///
/// [`MlsPendingMessage`] is the only entity for now which is bulk-deletable, so it is what these use.
/// Nothing here ever commits, so the database stays empty throughout and every outcome reflects
/// only the operations buffered in the transaction.
#[cfg(all(test, not(target_os = "unknown")))]
mod tests {
    use futures_lite::future;

    use super::*;
    use crate::{
        Database,
        entities::{ConversationId, MlsPendingMessage},
        traits::PrimaryKey as _,
    };

    const CONVERSATION_ID: &[u8] = b"conversation which buffers a message";

    fn pending_message() -> MlsPendingMessage {
        MlsPendingMessage {
            conversation_id: CONVERSATION_ID.to_owned(),
            message: b"a message which arrived before we could decrypt it".to_vec(),
        }
    }

    /// Bulk-delete every pending message of [`CONVERSATION_ID`].
    async fn clear_conversation(tx: &Transaction) {
        tx.bulk_remove::<MlsPendingMessage, ConversationId>(CONVERSATION_ID.to_vec().into())
            .await;
    }

    /// What `get_by_entity_id` reports for `message`.
    async fn outcome_for(tx: &Transaction, message: &MlsPendingMessage) -> ReadOutcome<MlsPendingMessage> {
        let entity_id = EntityId::from_primary_key::<MlsPendingMessage>(&message.primary_key());
        tx.get_by_entity_id(&entity_id).await
    }

    /// The documented property: an entity upserted in this transaction and then bulk-deleted
    /// reads back as deleted, not as present.
    #[test]
    fn an_upsert_covered_by_a_later_bulk_deletion_reads_as_deleted() {
        future::block_on(async {
            let store = Database::open_in_memory().unwrap();
            let tx = store.new_transaction().await.unwrap();
            let message = pending_message();

            tx.save(message.clone()).await.unwrap();
            clear_conversation(&tx).await;

            let outcome = outcome_for(&tx, &message).await;
            assert!(
                matches!(outcome.entity, Some(None)),
                "the upsert was covered by a later bulk deletion, so it must read as deleted, got {:?}",
                outcome.entity
            );
        });
    }

    /// The mirror image: only bulk deletions which come *after* the upsert can bury it.
    ///
    /// The filter is still reported, because it has to be applied to whatever the database
    /// produces for other entities; see the note on [`ReadOutcome`].
    #[test]
    fn an_upsert_after_a_bulk_deletion_reads_as_present() {
        future::block_on(async {
            let store = Database::open_in_memory().unwrap();
            let tx = store.new_transaction().await.unwrap();
            let message = pending_message();

            clear_conversation(&tx).await;
            tx.save(message.clone()).await.unwrap();

            let outcome = outcome_for(&tx, &message).await;
            let found = outcome
                .entity
                .clone()
                .expect("this transaction upserted the message, so the cache knows about it")
                .expect("the upsert came after the bulk deletion, so it must not have been filtered out");
            assert_eq!(*found, message);
            assert!(
                outcome.should_omit(&found),
                "the bulk deletion still has to be reported as a filter over database records"
            );
        });
    }

    /// Bulk deletions on both sides of the upsert: the later one still applies.
    ///
    /// Reading the whole filter list without regard to position would pass
    /// [`an_upsert_covered_by_a_later_bulk_deletion_reads_as_deleted`] and ignoring position
    /// entirely would pass [`an_upsert_after_a_bulk_deletion_reads_as_present`]; only this case
    /// distinguishes filtering by position from filtering by presence.
    #[test]
    fn an_upsert_straddled_by_bulk_deletions_reads_as_deleted() {
        future::block_on(async {
            let store = Database::open_in_memory().unwrap();
            let tx = store.new_transaction().await.unwrap();
            let message = pending_message();

            clear_conversation(&tx).await;
            tx.save(message.clone()).await.unwrap();
            clear_conversation(&tx).await;

            let outcome = outcome_for(&tx, &message).await;
            assert!(
                matches!(outcome.entity, Some(None)),
                "the second bulk deletion follows the upsert, so the message must read as deleted, got {:?}",
                outcome.entity
            );
        });
    }

    /// The documented limit of the property: with no upsert to attach it to, a bulk deletion is
    /// reported only as a filter, and the outcome itself says nothing.
    ///
    /// This is why the doc comment tells composing methods with database context to do their own
    /// bulk-deletion filtering.
    #[test]
    fn a_bulk_deletion_alone_yields_no_outcome_but_still_yields_a_filter() {
        future::block_on(async {
            let store = Database::open_in_memory().unwrap();
            let tx = store.new_transaction().await.unwrap();
            let message = pending_message();

            clear_conversation(&tx).await;

            let outcome = outcome_for(&tx, &message).await;
            assert!(
                outcome.entity.is_none(),
                "nothing in this transaction mutated this message individually, so the cache cannot speak for it"
            );
            assert!(
                outcome.should_omit(&message),
                "the caller must still be told to omit any instance the database produces"
            );
        });
    }
}
