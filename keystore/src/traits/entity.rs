use std::borrow::Borrow;

use async_trait::async_trait;

use crate::{
    CryptoKeystoreResult,
    traits::{EntityBase, KeyType},
};

/// Something which can be stored in our database.
///
/// It has a primary key, which uniquely identifies it.
#[cfg_attr(target_family = "wasm", async_trait(?Send))]
#[cfg_attr(not(target_family = "wasm"), async_trait)]
pub trait Entity: EntityBase {
    /// Each distinct `PrimaryKey` uniquely identifies either 0 or 1 instance.
    ///
    /// This constraint should be enforced at the DB level.
    type PrimaryKey: KeyType;

    /// Get this entity's primary key.
    fn primary_key(&self) -> Self::PrimaryKey;

    /// Get an entity by its primary key.
    ///
    /// For entites whose primary key has a distinct borrowed type, it is best to implement this as a direct
    /// passthrough:
    ///
    /// ```rust,ignore
    /// async fn get(conn: &mut Self::ConnectionType, key: &Self::PrimaryKey) -> CoreCryptoKeystoreResult<Option<Self>> {
    ///     <Self as EntityGetBorrowed>::get_borrowed(conn, key).await
    /// }
    /// ```
    async fn get(conn: &mut Self::ConnectionType, key: &Self::PrimaryKey) -> CryptoKeystoreResult<Option<Self>>;

    /// Count the number of entities of this type in the database.
    async fn count(conn: &mut Self::ConnectionType) -> CryptoKeystoreResult<u32>;

    /// Retrieve all entities of this type from the database.
    async fn load_all(conn: &mut Self::ConnectionType) -> CryptoKeystoreResult<Vec<Self>>;
}

/// An extension trait which should be implemented for all entities whose primary key has a distinct borrowed form.
///
/// i.e. `String`, `Vec<u8>`, etc.
#[cfg_attr(target_family = "wasm", async_trait(?Send))]
#[cfg_attr(not(target_family = "wasm"), async_trait)]
pub trait EntityGetBorrowed: Entity {
    /// Get an entity by a borrowed form of its primary key.
    ///
    /// The type signature here is somewhat complicated, but it breaks down simply: if our primary key is something
    /// like `Vec<u8>`, we want to be able to use this method even if what we have on hand is `&[u8]`.
    async fn get_borrowed<Q>(conn: &mut Self::ConnectionType, key: &Q) -> CryptoKeystoreResult<Option<Self>>
    where
        Self::PrimaryKey: Borrow<Q>,
        Q: KeyType;
}
