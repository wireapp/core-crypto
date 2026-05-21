use std::borrow::Borrow;

use async_trait::async_trait;
use core_crypto_keystore::{
    CryptoKeystoreResult, Database,
    connection::KeystoreDatabaseConnection,
    traits::{BorrowPrimaryKey, Entity, EntityGetBorrowed, FetchFromDatabase, KeyType, SearchableEntity},
};

/// This database only exposes immutable operations.
///
/// This makes it easier on a type level to get things right:
/// [`CoreCrypto`][crate::CoreCrypto] and [`Session`][crate::Session]
/// have access to the immutable variant, while
/// [`TransactionContext`][crate::transaction_context::TransactionContext]
/// can still access the mutable variant on request.
pub(crate) struct ImmutableDatabase(Database);

impl ImmutableDatabase {
    /// Get access to the version of this database which exposes
    /// mutating operations.
    pub(crate) fn mutable(&self) -> &Database {
        &self.0
    }
}

#[cfg_attr(not(target_os = "unknown"), async_trait)]
#[cfg_attr(target_os = "unknown", async_trait(?Send))]
impl FetchFromDatabase for ImmutableDatabase {
    async fn get<E>(&self, id: &E::PrimaryKey) -> CryptoKeystoreResult<Option<E>>
    where
        E: Entity<ConnectionType = KeystoreDatabaseConnection> + Clone + Send + Sync,
    {
        self.0.get::<E>(id).await
    }

    async fn count<E>(&self) -> CryptoKeystoreResult<u32>
    where
        E: Entity<ConnectionType = KeystoreDatabaseConnection> + Clone + Send + Sync,
    {
        self.0.count::<E>().await
    }

    async fn load_all<E>(&self) -> CryptoKeystoreResult<Vec<E>>
    where
        E: Entity<ConnectionType = KeystoreDatabaseConnection> + Clone + Send + Sync,
    {
        self.0.load_all::<E>().await
    }

    async fn get_borrowed<E>(&self, id: &<E as BorrowPrimaryKey>::BorrowedPrimaryKey) -> CryptoKeystoreResult<Option<E>>
    where
        E: EntityGetBorrowed<ConnectionType = KeystoreDatabaseConnection> + Clone + Send + Sync,
        E::PrimaryKey: Borrow<E::BorrowedPrimaryKey>,
        for<'a> &'a E::BorrowedPrimaryKey: KeyType,
    {
        self.0.get_borrowed::<E>(id).await
    }

    async fn search<E, SearchKey>(&self, search_key: &SearchKey) -> CryptoKeystoreResult<Vec<E>>
    where
        E: Entity<ConnectionType = KeystoreDatabaseConnection> + SearchableEntity<SearchKey> + Clone + Send + Sync,
        SearchKey: KeyType,
    {
        self.0.search::<E, SearchKey>(search_key).await
    }
}
