use std::{borrow::Borrow, sync::Arc};

use async_trait::async_trait;
use core_crypto_keystore::{
    CryptoKeystoreResult, Database,
    traits::{
        BorrowPrimaryKey, FetchFromDatabase, KeyType, UnifiedEntity, UnifiedEntityGetBorrowed, UnifiedSearchableEntity,
    },
};

/// This database only exposes immutable operations.
///
/// This makes it easier on a type level to get things right:
/// [`CoreCrypto`][crate::CoreCrypto] and [`Session`][crate::Session]
/// have access to the immutable variant, while
/// [`TransactionContext`][crate::transaction_context::TransactionContext]
/// can still access the mutable variant on request.
#[derive(Debug, Clone, derive_more::From)]
pub struct ImmutableDatabase(Arc<Database>);

#[cfg_attr(not(target_os = "unknown"), async_trait)]
#[cfg_attr(target_os = "unknown", async_trait(?Send))]
impl FetchFromDatabase for ImmutableDatabase {
    async fn get<E>(&self, id: &E::PrimaryKey) -> CryptoKeystoreResult<Option<E>>
    where
        E: UnifiedEntity + Clone + Send + Sync + 'static,
    {
        self.0.get::<E>(id).await
    }

    async fn count<E>(&self) -> CryptoKeystoreResult<u32>
    where
        E: UnifiedEntity + Clone + Send + Sync + 'static,
    {
        self.0.count::<E>().await
    }

    async fn load_all<E>(&self) -> CryptoKeystoreResult<Vec<E>>
    where
        E: UnifiedEntity + Clone + Send + Sync + 'static,
    {
        self.0.load_all::<E>().await
    }

    async fn get_borrowed<E>(&self, id: &<E as BorrowPrimaryKey>::BorrowedPrimaryKey) -> CryptoKeystoreResult<Option<E>>
    where
        E: UnifiedEntityGetBorrowed + Clone + Send + Sync + 'static,
        E::PrimaryKey: Borrow<E::BorrowedPrimaryKey>,
        for<'a> &'a E::BorrowedPrimaryKey: KeyType,
    {
        self.0.get_borrowed::<E>(id).await
    }

    async fn search<E, SearchKey>(&self, search_key: &SearchKey) -> CryptoKeystoreResult<Vec<E>>
    where
        E: UnifiedEntity + UnifiedSearchableEntity<SearchKey> + Clone + Send + Sync + 'static,
        SearchKey: KeyType,
    {
        self.0.search::<E, SearchKey>(search_key).await
    }
}
