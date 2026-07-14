use rusqlite::Connection;

use crate::{
    CryptoKeystoreResult,
    traits::{
        KeyType,
        primary_key::{BorrowPrimaryKey, PrimaryKey},
    },
};

/// Something which can be stored in our database.
///
/// It has a primary key, which uniquely identifies it.
pub trait Entity: PrimaryKey + Sized {
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

pub trait EntityGetBorrowed: Entity + BorrowPrimaryKey {
    /// Get an entity by a borrowed form of its primary key.
    fn get_borrowed(conn: &Connection, key: &Self::BorrowedPrimaryKey) -> CryptoKeystoreResult<Option<Self>>
    where
        for<'pk> &'pk Self::BorrowedPrimaryKey: KeyType;
}
