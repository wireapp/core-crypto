//! These methods allow for read-only operations on the entities in the transaction,
//! without considering the database itself.

use std::{borrow::Cow, sync::Arc};

use super::dynamic_dispatch::EntityId;
use crate::{
    CryptoKeystoreResult,
    traits::{BorrowPrimaryKey, Entity, KeyType, SearchableEntity},
    transaction::KeystoreTransaction,
};

impl KeystoreTransaction {
    async fn find_in_cache<E>(&self, entity_id: &EntityId) -> Option<Arc<E>>
    where
        E: 'static + Entity + Send + Sync,
    {
        let cache_guard = self.cache.read().await;
        cache_guard.get(entity_id).and_then(|entity| entity.downcast())
    }

    /// The result of this function will have different contents for different scenarios:
    /// * `Some(Some(E))` - the transaction cache contains the record
    /// * `Some(None)` - the deletion of the record has been cached
    /// * `None` - there is no information about the record in the cache
    async fn get_by_entity_id<E>(&self, entity_id: &EntityId) -> Option<Option<Arc<E>>>
    where
        E: 'static + Entity + Send + Sync,
    {
        // when applying our transaction to the real database, we delete after inserting,
        // so here we have to check for deletion before we check for existing values
        let deleted_list = self.deleted.read().await;
        if deleted_list.contains(entity_id) {
            return Some(None);
        }

        self.find_in_cache::<E>(entity_id).await.map(Some)
    }

    /// The result of this function will have different contents for different scenarios:
    /// * `Some(Some(E))` - the transaction cache contains the record
    /// * `Some(None)` - the deletion of the record has been cached
    /// * `None` - there is no information about the record in the cache
    pub(crate) async fn get<E>(&self, id: &E::PrimaryKey) -> Option<Option<Arc<E>>>
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
    pub(crate) async fn get_borrowed<E>(&self, id: &E::BorrowedPrimaryKey) -> Option<Option<Arc<E>>>
    where
        E: 'static + Entity + BorrowPrimaryKey + Send + Sync,
    {
        let entity_id = EntityId::from_borrowed_primary_key::<E>(id)?;
        self.get_by_entity_id(&entity_id).await
    }

    pub(super) async fn find_all_in_cache<E>(&self) -> Vec<Arc<E>>
    where
        E: 'static + Entity + Send + Sync,
    {
        let cache_guard = self.cache.read().await;
        cache_guard
            .values()
            .filter_map(|entity| entity.downcast::<E>())
            .collect()
    }

    async fn search_in_cache<E, SearchKey>(&self, search_key: &SearchKey) -> Vec<Arc<E>>
    where
        E: 'static + Entity + SearchableEntity<SearchKey> + Send + Sync,
        SearchKey: KeyType,
    {
        let cache_guard = self.cache.read().await;
        cache_guard
            .values()
            .filter_map(|entity| entity.downcast::<E>())
            .filter(|entity| entity.matches(search_key))
            .collect()
    }

    pub(crate) async fn find_all<E>(&self, persisted_records: Vec<E>) -> CryptoKeystoreResult<Vec<E>>
    where
        E: 'static + Clone + Entity + Send + Sync,
    {
        let cached_records = self.find_all_in_cache().await;
        let merged_records = self
            .merge_records(
                cached_records.iter().map(Arc::as_ref).map(Cow::Borrowed),
                persisted_records.into_iter().map(Cow::Owned),
            )
            .await;
        Ok(merged_records)
    }

    pub(crate) async fn search<E, SearchKey>(
        &self,
        persisted_records: Vec<E>,
        search_key: &SearchKey,
    ) -> CryptoKeystoreResult<Vec<E>>
    where
        E: 'static + Clone + Entity + SearchableEntity<SearchKey> + Send + Sync,
        SearchKey: KeyType,
    {
        let cached_records = self.search_in_cache(search_key).await;
        let merged_records = self
            .merge_records(
                cached_records.iter().map(Arc::as_ref).map(Cow::Borrowed),
                persisted_records.into_iter().map(Cow::Owned),
            )
            .await;
        Ok(merged_records)
    }
}
