use std::{borrow::Borrow, convert::Infallible};

use async_trait::async_trait;
use openmls::prelude::CryptoError;

use crate::{
    CryptoKeystoreError, CryptoKeystoreMls, CryptoKeystoreResult,
    traits::{
        EntityBase, KeyType, OwnedKeyType,
        primary_key::{BorrowPrimaryKey, PrimaryKey},
    },
};

/// Something which can be stored in our database.
///
/// It has a primary key, which uniquely identifies it.
#[cfg_attr(target_family = "wasm", async_trait(?Send))]
#[cfg_attr(not(target_family = "wasm"), async_trait)]
pub trait Entity: EntityBase + PrimaryKey {
    /// The domain type, for openmls types this will not be Self
    type Target: From<Self> + Into<Self> + Send + Sync;

    /// Get an entity by its primary key.
    ///
    /// For entites whose primary key has a distinct borrowed type, it is best to implement this as a direct
    /// passthrough:
    ///
    /// ```rust,ignore
    /// async fn get(conn: &mut Self::ConnectionType, key: &Self::PrimaryKey) -> CoreCryptoKeystoreResult<Option<Self>> {
    ///     Self::get_borrowed(conn, key).await
    /// }
    /// ```
    async fn get(conn: &mut Self::ConnectionType, key: &Self::PrimaryKey) -> CryptoKeystoreResult<Option<Self>>;

    /// Count the number of entities of this type in the database.
    async fn count(conn: &mut Self::ConnectionType) -> CryptoKeystoreResult<u32>;

    /// Retrieve all entities of this type from the database.
    async fn load_all(conn: &mut Self::ConnectionType) -> CryptoKeystoreResult<Vec<Self>>;
}

#[cfg_attr(target_family = "wasm", async_trait(?Send))]
#[cfg_attr(not(target_family = "wasm"), async_trait)]
pub trait EntityGetBorrowed: Entity + BorrowPrimaryKey {
    /// Get an entity by a borrowed form of its primary key.
    async fn get_borrowed(
        conn: &mut Self::ConnectionType,
        key: &Self::BorrowedPrimaryKey,
    ) -> CryptoKeystoreResult<Option<Self>>
    where
        for<'pk> &'pk Self::BorrowedPrimaryKey: KeyType;
}
