//! As transactions are now first-class entities which will be floating around in their own right,
//! we impl `FetchFromDatabase` as a convenience.
//!
//! It doesn't matter whether someone is holding a `Database` or a `KeystoreTransaction` instance;
//! the two `FetchFromDatabase` implementations will always agree.

use std::{borrow::Borrow, sync::Arc};

use async_trait::async_trait;

use crate::{
    CryptoKeystoreResult,
    traits::{BorrowPrimaryKey, Entity, EntityGetBorrowed, FetchFromDatabase, KeyType, SearchableEntity},
    transaction::Transaction,
};

#[cfg_attr(target_os = "unknown", async_trait(?Send))]
#[cfg_attr(not(target_os = "unknown"), async_trait)]
impl FetchFromDatabase for Transaction {
    async fn get<E>(&self, id: &E::PrimaryKey) -> CryptoKeystoreResult<Option<E>>
    where
        E: 'static + Entity + Clone + Send + Sync,
    {
        if let Some(result) = <Self>::get::<E>(self, id).await {
            return Ok(result.map(Arc::unwrap_or_clone));
        };

        // Otherwise get it from the database
        let conn = self.database.conn().await;
        E::get(&conn, id)
    }

    async fn get_borrowed<E>(&self, id: &<E as BorrowPrimaryKey>::BorrowedPrimaryKey) -> CryptoKeystoreResult<Option<E>>
    where
        E: 'static + EntityGetBorrowed + Clone + Send + Sync,
        E::PrimaryKey: Borrow<E::BorrowedPrimaryKey>,
        for<'a> &'a E::BorrowedPrimaryKey: KeyType,
    {
        if let Some(result) = <Self>::get_borrowed::<E>(self, id).await {
            return Ok(result.map(Arc::unwrap_or_clone));
        }

        let conn = self.database.conn().await;
        E::get_borrowed(&conn, id)
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

    async fn load_all<E>(&self) -> CryptoKeystoreResult<Vec<E>>
    where
        E: 'static + Entity + Clone + Send + Sync,
    {
        let conn = self.database.conn().await;
        let persisted_records = E::load_all(&conn)?;

        <Self>::find_all(self, persisted_records).await
    }

    async fn search<E, SearchKey>(&self, search_key: &SearchKey) -> CryptoKeystoreResult<Vec<E>>
    where
        E: 'static + Entity + SearchableEntity<SearchKey> + Clone + Send + Sync,
        SearchKey: KeyType,
    {
        let conn = self.database.conn().await;
        let persisted_records = E::find_all_matching(&conn, search_key)?;

        <Self>::search(self, persisted_records, search_key).await
    }
}
