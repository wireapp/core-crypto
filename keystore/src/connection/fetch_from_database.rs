use std::{borrow::Borrow, sync::Arc};

use async_trait::async_trait;

use crate::{
    CryptoKeystoreError, CryptoKeystoreResult, Database,
    traits::{BorrowPrimaryKey, Entity, EntityGetBorrowed, FetchFromDatabase, KeyType, SearchableEntity},
    transaction::ReadOutcome,
};

/// It's not an error if there is no transaction when fetching from database,
/// so map that to an empty read outcome (no found entity, no filters).
fn no_transaction_to_default_read_outcome<E>(err: CryptoKeystoreError) -> CryptoKeystoreResult<ReadOutcome<E>> {
    match err {
        CryptoKeystoreError::MutatingOperationWithoutTransaction => Ok(ReadOutcome::default()),
        _ => Err(err),
    }
}

#[cfg_attr(target_os = "unknown", async_trait(?Send))]
#[cfg_attr(not(target_os = "unknown"), async_trait)]
impl FetchFromDatabase for Database {
    async fn get<E>(&self, id: &E::PrimaryKey) -> CryptoKeystoreResult<Option<E>>
    where
        E: 'static + Entity + Clone + Send + Sync,
    {
        let read_outcome = self
            .with_transaction(async |transaction| Ok(transaction.get::<E>(id).await))
            .await
            .or_else(no_transaction_to_default_read_outcome)?;

        if let Some(record) = read_outcome.entity {
            return Ok(record.map(Arc::unwrap_or_clone));
        }

        // Otherwise get it from the database
        let conn = self.conn().await;
        let db_entity = E::get(&conn, id)?.filter(|entity| !read_outcome.should_omit(entity));

        Ok(db_entity)
    }

    async fn get_borrowed<E>(&self, id: &<E as BorrowPrimaryKey>::BorrowedPrimaryKey) -> CryptoKeystoreResult<Option<E>>
    where
        E: 'static + EntityGetBorrowed + Clone + Send + Sync,
        E::PrimaryKey: Borrow<E::BorrowedPrimaryKey>,
        for<'a> &'a E::BorrowedPrimaryKey: KeyType,
    {
        let read_outcome = self
            .with_transaction(async |transaction| Ok(transaction.get_borrowed::<E>(id).await))
            .await
            .or_else(no_transaction_to_default_read_outcome)?;

        if let Some(cached_record) = read_outcome.entity {
            return Ok(cached_record.map(Arc::unwrap_or_clone));
        }

        // Otherwise get it from the database
        let conn = self.conn().await;
        let db_entity = E::get_borrowed(&conn, id)?.filter(|entity| !read_outcome.should_omit(entity));
        Ok(db_entity)
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

        self.merge_with_transaction(persisted_records, async |transaction, persisted_records| {
            Ok(transaction.find_all(persisted_records).await.collect())
        })
        .await
    }

    async fn search<E, SearchKey>(&self, search_key: &SearchKey) -> CryptoKeystoreResult<Vec<E>>
    where
        E: 'static + Entity + SearchableEntity<SearchKey> + Clone + Send + Sync,
        SearchKey: KeyType,
    {
        let conn = self.conn().await;
        let persisted_records = E::find_all_matching(&conn, search_key)?;

        self.merge_with_transaction(persisted_records, async |transaction, persisted_records| {
            Ok(transaction.search(persisted_records, search_key).await.collect())
        })
        .await
    }
}
