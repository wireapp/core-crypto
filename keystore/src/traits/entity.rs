use std::borrow::Borrow;

use async_trait::async_trait;
use rusqlite::Connection;

use crate::{
    CryptoKeystoreResult,
    traits::{
        EntityBase, KeyType, OwnedKeyType,
        primary_key::{BorrowPrimaryKey, PrimaryKey},
    },
};

/// Something which can be stored in our database.
///
/// It has a primary key, which uniquely identifies it.
#[cfg_attr(target_os = "unknown", async_trait(?Send))]
#[cfg_attr(not(target_os = "unknown"), async_trait)]
pub trait Entity: EntityBase + PrimaryKey {
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

#[cfg_attr(target_os = "unknown", async_trait(?Send))]
#[cfg_attr(not(target_os = "unknown"), async_trait)]
pub trait EntityGetBorrowed: Entity + BorrowPrimaryKey {
    /// Get an entity by a borrowed form of its primary key.
    async fn get_borrowed(
        conn: &mut Self::ConnectionType,
        key: &Self::BorrowedPrimaryKey,
    ) -> CryptoKeystoreResult<Option<Self>>
    where
        for<'pk> &'pk Self::BorrowedPrimaryKey: KeyType;
}

/// Something which can be stored in our database.
///
/// It has a primary key, which uniquely identifies it.
//
// During WPB-23775 we need to rename this and all other `Unified*` traits to just the bare form
pub trait UnifiedEntity: PrimaryKey + Sized {
    /// The table name for this entity
    const COLLECTION_NAME: &'static str;

    /// Get an entity by its primary key.
    ///
    /// For entites whose primary key has a distinct borrowed type, it is best to implement this as a direct
    /// passthrough:
    ///
    /// ```rust,ignore
    /// fn get(conn: &Connection, key: &Self::PrimaryKey) -> CoreCryptoKeystoreResult<Option<Self>> {
    ///     Self::get_borrowed(conn, key).await
    /// }
    /// ```
    fn get(conn: &Connection, key: &Self::PrimaryKey) -> CryptoKeystoreResult<Option<Self>>;

    /// Count the number of entities of this type in the database.
    fn count(conn: &Connection) -> CryptoKeystoreResult<u32>;

    /// Retrieve all entities of this type from the database.
    fn load_all(conn: &Connection) -> CryptoKeystoreResult<Vec<Self>>;
}

pub trait UnifiedEntityGetBorrowed: UnifiedEntity + BorrowPrimaryKey {
    /// Get an entity by a borrowed form of its primary key.
    fn get_borrowed(conn: &Connection, key: &Self::BorrowedPrimaryKey) -> CryptoKeystoreResult<Option<Self>>
    where
        for<'pk> &'pk Self::BorrowedPrimaryKey: KeyType;
}
