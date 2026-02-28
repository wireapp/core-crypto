use std::borrow::Borrow;

use async_trait::async_trait;

use crate::{
    CryptoKeystoreResult,
    connection::KeystoreDatabaseConnection,
    traits::{
        BorrowPrimaryKey, Entity, EntityBase, EntityGetBorrowed, KeyType, PrimaryKey, SearchableEntity, UniqueEntity,
        UniqueEntityExt,
    },
    transaction::transaction_store::CachedEntity,
};

/// Interface to fetch from the database either from the connection directly or through a
/// transaction.
///
/// Fundamentally these are convenience methods, allowing you to do `let n_foos = database.count::<Foo>()`
/// instead of `Foo::count(&mut database.conn)`.
#[cfg_attr(target_family = "wasm", async_trait(?Send))]
#[cfg_attr(not(target_family = "wasm"), async_trait)]
pub trait FetchFromDatabase: Send + Sync {
    /// Get an instance of `E` from the database by its primary key.
    async fn get<E>(&self, id: &E::PrimaryKey) -> CryptoKeystoreResult<Option<E>>
    where
        E: CachedEntity<ConnectionType = KeystoreDatabaseConnection> + Clone + Send + Sync;

    /// Count the number of `E`s in the database.
    async fn count<E>(&self) -> CryptoKeystoreResult<u32>
    where
        E: CachedEntity<ConnectionType = KeystoreDatabaseConnection> + Clone + Send + Sync;

    /// Load all `E`s from the database.
    async fn load_all<E>(&self) -> CryptoKeystoreResult<Vec<E>>
    where
        E: CachedEntity<ConnectionType = KeystoreDatabaseConnection> + Clone + Send + Sync;

    /// Get an instance of `E` from the database by the borrowed form of its primary key.
    async fn get_borrowed<E>(
        &self,
        id: &<E as BorrowPrimaryKey>::BorrowedPrimaryKey,
    ) -> CryptoKeystoreResult<Option<E>>
    where
        E: EntityGetBorrowed<ConnectionType = KeystoreDatabaseConnection> + CachedEntity + Clone + Send + Sync,
        E::PrimaryKey: Borrow<E::BorrowedPrimaryKey>,
        for<'a> &'a E::BorrowedPrimaryKey: KeyType;

    /// Get the requested unique entity from the database.
    async fn get_unique<'a, U>(&self) -> CryptoKeystoreResult<Option<U>>
    where
        U: UniqueEntityExt<'a> + CachedEntity<ConnectionType = KeystoreDatabaseConnection> + Clone + Send + Sync,
    {
        self.get::<U>(&U::KEY).await
    }

    /// Determine whether a unique entity is present in the database.
    async fn exists<'a, U>(&self) -> CryptoKeystoreResult<bool>
    where
        U: UniqueEntityExt<'a> + CachedEntity<ConnectionType = KeystoreDatabaseConnection> + Clone + Send + Sync,
    {
        let count = self.count::<U>().await?;
        Ok(count > 0)
    }

    /// Search for relevant instances of `E` given a search key.
    async fn search<E, SearchKey>(&self, search_key: &SearchKey) -> CryptoKeystoreResult<Vec<E>>
    where
        E: CachedEntity<ConnectionType = KeystoreDatabaseConnection>
            + SearchableEntity<SearchKey>
            + Clone
            + Send
            + Sync,
        SearchKey: KeyType;
}
