//! These methods allow for read-only operations on the entities in the transaction,
//! without considering the database itself.

use std::{collections::HashMap, sync::Arc};

use super::dynamic_dispatch::EntityId;
use crate::{
    traits::{BorrowPrimaryKey, Entity, KeyType, SearchableEntity},
    transaction::{ReadOutcome, Transaction},
};

impl Transaction {
    /// Find an entity by its id.
    ///
    /// The result of this function will vary for different scenarios:
    ///
    /// * `Some(Some(E))` - the transaction cache contains the record
    /// * `Some(None)` - the deletion of the record has been cached
    /// * `None` - there is no information about the record in the cache
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
        let mut outcome = ReadOutcome::default();

        // consider the operations in reverse
        let operations = self.operations.read().await;
        for operation in operations.iter().rev() {
            // take the last mutation for the entity while it's unknown
            if outcome.entity.is_none() {
                if let Some(mutation) = operation.is_mutation_for::<E>(entity_id) {
                    outcome.entity = Some(mutation);

                    // but if we've already seen a relevant bulk deletion, it's actually gone
                    if let Some(Some(entity)) = &outcome.entity
                        && outcome.should_omit(entity)
                    {
                        outcome.entity = Some(None);
                    }
                }
            }

            // if this operation is a bulk deletion, record that; we'll need it later
            if let Some(should_omit) = operation.as_bulk_delete() {
                outcome.filters.push(Box::new(should_omit));
            }
        }

        outcome
    }

    /// The result of this function will have different contents for different scenarios:
    /// * `Some(Some(E))` - the transaction cache contains the record
    /// * `Some(None)` - the deletion of the record has been cached
    /// * `None` - there is no information about the record in the cache
    pub(crate) async fn get<E>(&self, id: &E::PrimaryKey) -> ReadOutcome<E>
    where
        E: 'static + Entity + Send + Sync,
    {
        let entity_id = EntityId::from_primary_key::<E>(id)?;
        self.get_by_entity_id(&entity_id).await
    }

    /// The result of this function will have different contents for different scenarios:
    /// * `Some(Some(E))` - the transaction cache contains the record
    /// * `Some(None)` - the deletion of the record has been cached
    /// * `None` - there is no information about the record in the cache
    pub(crate) async fn get_borrowed<E>(&self, id: &E::BorrowedPrimaryKey) -> ReadOutcome<E>
    where
        E: 'static + Entity + BorrowPrimaryKey + Send + Sync,
    {
        let entity_id = EntityId::from_borrowed_primary_key::<E>(id)?;
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
    pub(super) async fn find_all_in_cache<E>(&self) -> impl Iterator<Item = Arc<E>>
    where
        E: 'static + Entity + Send + Sync,
    {
        let operations = self.operations.read().await;

        let mut cache = HashMap::new();
        for operation in operations.iter() {
            if let Some(entity) = operation.as_upsert::<E>() {
                let entity_id = EntityId::from_entity(&*entity).expect("TODO: make entity ids infallible");
                cache.insert(entity_id, entity);
            }
            if let Some(entity_id) = operation.as_delete::<E>() {
                cache.remove(&entity_id);
            }
            if let Some(should_delete) = operation.as_bulk_delete::<E>() {
                cache.retain(|_entity_id, entity| !should_delete(entity));
            }
        }

        cache.into_values()
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
            .filter(|entity| entity.matches(search_key))
    }

    /// Find all the entities of type `E` in the database as modified by the operations in this transaction.
    pub(crate) async fn find_all<E>(&self, persisted_records: impl IntoIterator<Item = E>) -> impl Iterator<Item = E>
    where
        E: 'static + Clone + Entity + Send + Sync,
    {
        let cached_records = self.find_all_in_cache::<E>().await;
        self.merge_records(cached_records.map(Arc::unwrap_or_clone), persisted_records)
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
