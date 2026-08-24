//! As transactions are now first-class entities which will be floating around in their own right,
//! we impl [`FetchFromDatabase`] as a convenience.
//!
//! It doesn't matter whether someone is holding a [`Database`][crate::Database] or a
//! [`Transaction`] instance; every implementation of the trait will always agree.

use std::sync::Arc;

use async_trait::async_trait;

use crate::{
    CryptoKeystoreResult,
    traits::{BorrowPrimaryKey, Entity, EntityGetBorrowed, FetchFromDatabase, SearchableEntity},
    transaction::Transaction,
};

#[cfg_attr(target_os = "unknown", async_trait(?Send))]
#[cfg_attr(not(target_os = "unknown"), async_trait)]
impl FetchFromDatabase for Transaction {
    async fn get<E>(&self, id: &E::PrimaryKey) -> CryptoKeystoreResult<Option<Arc<E>>>
    where
        E: 'static + Entity + Clone + Send + Sync,
    {
        let read_outcome = <Self>::get::<E>(self, id).await;
        if let Some(result) = read_outcome.entity {
            return Ok(result);
        };

        // Otherwise get it from the database
        let conn = self.database.conn().await;
        let db_entity = E::get(&conn, id)?.filter(|entity| !read_outcome.should_omit(entity));
        Ok(db_entity.map(Arc::new))
    }

    async fn get_borrowed<E>(
        &self,
        id: <E as BorrowPrimaryKey>::BorrowedPrimaryKey<'_>,
    ) -> CryptoKeystoreResult<Option<Arc<E>>>
    where
        E: 'static + EntityGetBorrowed + Clone + Send + Sync,
    {
        let read_outcome = <Self>::get_borrowed::<E>(self, &id).await;
        if let Some(result) = read_outcome.entity {
            return Ok(result);
        }

        let conn = self.database.conn().await;
        let db_entity = E::get_borrowed(&conn, id)?.filter(|entity| !read_outcome.should_omit(entity));
        Ok(db_entity.map(Arc::new))
    }

    async fn count<E>(&self) -> CryptoKeystoreResult<u32>
    where
        E: 'static + Entity + Clone + Send + Sync,
    {
        // Unfortunately, we have to do this because of possible record id overlap
        // between cache and db.
        let count = self.load_all::<E>().await?.len();
        Ok(count as _)
    }

    async fn load_all<E>(&self) -> CryptoKeystoreResult<Vec<Arc<E>>>
    where
        E: 'static + Entity + Clone + Send + Sync,
    {
        let conn = self.database.conn().await;
        let persisted_records = E::load_all(&conn)?.into_iter().map(Arc::new);

        Ok(<Self>::find_all(self, persisted_records).await.collect())
    }

    async fn search<E, SearchKey>(&self, search_key: &SearchKey) -> CryptoKeystoreResult<Vec<Arc<E>>>
    where
        E: 'static + Entity + SearchableEntity<SearchKey> + Clone + Send + Sync,
        SearchKey: Send + Sync + ?Sized,
    {
        let conn = self.database.conn().await;
        let persisted_records = E::find_all_matching(&conn, search_key)?.into_iter().map(Arc::new);

        Ok(<Self>::search(self, persisted_records, search_key).await.collect())
    }
}
