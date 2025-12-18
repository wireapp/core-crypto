use async_trait::async_trait;

use crate::{
    CryptoKeystoreResult,
    connection::KeystoreDatabaseConnection,
    traits::{BorrowPrimaryKey, Entity, UniqueEntity, UniqueEntityExt},
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
    async fn get<E>(&self, id: &<E as Entity>::PrimaryKey) -> CryptoKeystoreResult<Option<E>>
    where
        E: Entity<ConnectionType = KeystoreDatabaseConnection>;

    /// Count the number of `E`s in the database.
    async fn count<E>(&self) -> CryptoKeystoreResult<u32>
    where
        E: Entity<ConnectionType = KeystoreDatabaseConnection>;

    /// Load all `E`s from the database.
    async fn load_all<E>(&self) -> CryptoKeystoreResult<Vec<E>>
    where
        E: Entity<ConnectionType = KeystoreDatabaseConnection>;

    /// Get an instance of `E` from the database by the borrowed form of its primary key.
    async fn get_borrowed<E>(
        &self,
        id: &<E as BorrowPrimaryKey>::BorrowedPrimaryKey,
    ) -> CryptoKeystoreResult<Option<E>>
    where
        E: BorrowPrimaryKey;

    /// Get the requested unique entity from the database.
    async fn get_unique<'a, U>(&self) -> CryptoKeystoreResult<Option<U>>
    where
        U: UniqueEntityExt<'a>;

    /// Determine whether a unique entity is present in the database.
    async fn exists<'a, U>(&self) -> CryptoKeystoreResult<bool>
    where
        U: UniqueEntityExt<'a>;
}
