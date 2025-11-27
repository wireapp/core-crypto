use async_trait::async_trait;

use crate::{
    CryptoKeystoreResult,
    traits::entity_transaction_ext::EntityTransactionExt,
    traits::{Entity, EntityBase},
};

/// A unique entity can appear either 0 or 1 times in the database.
pub trait UniqueEntity: EntityBase<ConnectionType = crate::connection::KeystoreDatabaseConnection> + Entity {
    /// The id used as they key when storing this entity in a KV store.
    const KEY: <Self as Entity>::PrimaryKey;
}

/// Unique entities get some convenience methods implemented automatically.
#[cfg_attr(target_family = "wasm", async_trait(?Send))]
#[cfg_attr(not(target_family = "wasm"), async_trait)]
pub trait UniqueEntityExt<'a>: UniqueEntity + EntityTransactionExt<'a> {
    /// Get this unique entity from the database.
    async fn get_unique(conn: &mut Self::ConnectionType) -> CryptoKeystoreResult<Option<Self>>;

    /// Set this unique entity into the database, replacing it if it already exists.
    ///
    /// Returns `true` if the entity previously existed and was replaced, or
    /// `false` if it was not removed and this was a pure insertion.
    async fn set_and_replace(&self, tx: &Self::Transaction) -> CryptoKeystoreResult<bool>;

    /// Set this unique entity into the database if it does not already exist.
    ///
    /// Returns `true` if the entity was saved, or `false` if it aborted due to an already-existing entity.
    async fn set_if_absent(&self, tx: &Self::Transaction) -> CryptoKeystoreResult<bool>;

    /// Returns whether or not the database contains an instance of this unique entity.
    async fn exists(conn: &mut Self::ConnectionType) -> CryptoKeystoreResult<bool>;
}

#[cfg_attr(target_family = "wasm", async_trait(?Send))]
#[cfg_attr(not(target_family = "wasm"), async_trait)]
impl<'a, E> UniqueEntityExt<'a> for E
where
    E: UniqueEntity + EntityTransactionExt<'a> + Sync,
    <E as EntityTransactionExt<'a>>::Transaction: Sync,
{
    /// Get this unique entity from the database.
    async fn get_unique(conn: &mut Self::ConnectionType) -> CryptoKeystoreResult<Option<Self>> {
        Self::get(conn, &Self::KEY).await
    }

    /// Set this unique entity into the database, replacing it if it already exists.
    ///
    /// Returns `true` if the entity previously existed and was replaced, or
    /// `false` if it was not removed and this was a pure insertion.
    async fn set_and_replace(&self, tx: &Self::Transaction) -> CryptoKeystoreResult<bool> {
        let deleted = Self::delete(tx, &Self::KEY).await?;
        self.save(tx).await?;
        Ok(deleted)
    }

    /// Set this unique entity into the database if it does not already exist.
    ///
    /// Returns `true` if the entity was saved, or `false` if it aborted due to an already-existing entity.
    async fn set_if_absent(&self, tx: &Self::Transaction) -> CryptoKeystoreResult<bool> {
        let count = <Self as EntityTransactionExt>::count(tx).await?;
        if count > 0 {
            return Ok(false);
        }
        self.save(tx).await?;
        Ok(true)
    }

    /// Returns whether or not the database contains an instance of this unique entity.
    async fn exists(conn: &mut Self::ConnectionType) -> CryptoKeystoreResult<bool> {
        <Self as Entity>::count(conn).await.map(|count| count > 0)
    }
}
