use std::{borrow::Borrow, sync::Arc};

use async_trait::async_trait;

use crate::{
    CryptoKeystoreResult, Database,
    traits::{BorrowPrimaryKey, Entity, EntityGetBorrowed, FetchFromDatabase, KeyType, SearchableEntity},
};

#[cfg_attr(target_os = "unknown", async_trait(?Send))]
#[cfg_attr(not(target_os = "unknown"), async_trait)]
impl FetchFromDatabase for Database {
    async fn get<E>(&self, id: &E::PrimaryKey) -> CryptoKeystoreResult<Option<E>>
    where
        E: 'static + Entity + Clone + Send + Sync,
    {
        // If a transaction is in progress...
        if let Some(transaction) = self.transaction.lock().await.as_ref()
            //... and it has information about this entity, ...
            && let Some(cached_record) = transaction.get(id).await
        {
            return Ok(cached_record.map(Arc::unwrap_or_clone));
        }

        // Otherwise get it from the database
        let conn = self.conn().await;
        E::get(&conn, id)
    }

    async fn get_borrowed<E>(&self, id: &<E as BorrowPrimaryKey>::BorrowedPrimaryKey) -> CryptoKeystoreResult<Option<E>>
    where
        E: 'static + EntityGetBorrowed + Clone + Send + Sync,
        E::PrimaryKey: Borrow<E::BorrowedPrimaryKey>,
        for<'a> &'a E::BorrowedPrimaryKey: KeyType,
    {
        // If a transaction is in progress...
        if let Some(transaction) = self.transaction.lock().await.as_ref()
            //... and it has information about this entity, ...
            && let Some(cached_record) = transaction.get_borrowed(id).await
        {
            return Ok(cached_record.map(Arc::unwrap_or_clone));
        }

        // Otherwise get it from the database
        let conn = self.conn().await;
        E::get_borrowed(&conn, id)
    }

    async fn count<E>(&self) -> CryptoKeystoreResult<u32>
    where
        E: 'static + Entity + Clone + Send + Sync,
    {
        if self.transaction.lock().await.is_some() {
            // Unfortunately, we have to do this because of possible record id overlap
            // between cache and db.
            let count = self.load_all::<E>().await?.len();
            Ok(count as _)
        } else {
            let conn = self.conn().await;
            E::count(&conn)
        }
    }

    async fn load_all<E>(&self) -> CryptoKeystoreResult<Vec<E>>
    where
        E: 'static + Entity + Clone + Send + Sync,
    {
        let conn = self.conn().await;
        let persisted_records = E::load_all(&conn)?;

        let transaction_guard = self.transaction.lock().await;
        let Some(transaction) = transaction_guard.as_ref() else {
            return Ok(persisted_records);
        };
        transaction.find_all(persisted_records).await
    }

    async fn search<E, SearchKey>(&self, search_key: &SearchKey) -> CryptoKeystoreResult<Vec<E>>
    where
        E: 'static + Entity + SearchableEntity<SearchKey> + Clone + Send + Sync,
        SearchKey: KeyType,
    {
        let conn = self.conn().await;
        let persisted_records = E::find_all_matching(&conn, search_key)?;

        let transaction_guard = self.transaction.lock().await;
        let Some(transaction) = transaction_guard.as_ref() else {
            return Ok(persisted_records);
        };

        transaction.search(persisted_records, search_key).await
    }
}
