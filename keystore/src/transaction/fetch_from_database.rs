use std::sync::Arc;

use async_trait::async_trait;

use crate::{
    CryptoKeystoreResult, Transaction,
    traits::{BorrowPrimaryKey, Entity, EntityGetBorrowed, FetchFromDatabase, SearchableEntity},
};

#[cfg_attr(target_os = "unknown", async_trait(?Send))]
#[cfg_attr(not(target_os = "unknown"), async_trait)]
impl FetchFromDatabase for Transaction {
    async fn get<E>(&self, id: &E::PrimaryKey) -> CryptoKeystoreResult<Option<Arc<E>>>
    where
        E: 'static + Entity + Clone + Send + Sync,
    {
        let conn = self.conn()?;
        let db_entity = E::get(&conn, id)?;
        Ok(db_entity.map(Arc::new))
    }

    async fn get_borrowed<E>(
        &self,
        id: <E as BorrowPrimaryKey>::BorrowedPrimaryKey<'_>,
    ) -> CryptoKeystoreResult<Option<Arc<E>>>
    where
        E: 'static + EntityGetBorrowed + Clone + Send + Sync,
    {
        let conn = self.conn()?;
        let db_entity = E::get_borrowed(&conn, id)?;
        Ok(db_entity.map(Arc::new))
    }

    async fn count<E>(&self) -> CryptoKeystoreResult<u32>
    where
        E: 'static + Entity + Clone + Send + Sync,
    {
        let conn = self.conn()?;
        E::count(&conn)
    }

    async fn load_all<E>(&self) -> CryptoKeystoreResult<Vec<Arc<E>>>
    where
        E: 'static + Entity + Clone + Send + Sync,
    {
        let conn = self.conn()?;
        let items = E::load_all(&conn)?.into_iter().map(Arc::new).collect();
        Ok(items)
    }

    async fn search<E, SearchKey>(&self, search_key: &SearchKey) -> CryptoKeystoreResult<Vec<Arc<E>>>
    where
        E: 'static + Entity + SearchableEntity<SearchKey> + Clone + Send + Sync,
        SearchKey: Send + Sync + ?Sized,
    {
        let conn = self.conn()?;
        let items = E::find_all_matching(&conn, search_key)?
            .into_iter()
            .map(Arc::new)
            .collect();
        Ok(items)
    }
}
