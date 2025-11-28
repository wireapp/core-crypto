use crate::{CryptoKeystoreResult, Entity, EntityBase, traits::entity_transaction_ext::EntityTransactionExt};

/// A unique entity can appear either 0 or 1 times in the database.
pub trait UniqueEntity: EntityBase<ConnectionType = crate::connection::KeystoreDatabaseConnection> + Entity {
    /// The id used as they key when storing this entity in a KV store.
    const KEY: <Self as Entity>::PrimaryKey;
}

/// Unique entities get some convenience methods implemented automatically.
#[cfg_attr(target_family = "wasm", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_family = "wasm"), async_trait::async_trait)]
pub trait UniqueEntityExt<'a>: UniqueEntity + EntityTransactionExt<'a> {
    /// Get this unique entity from the database.
    async fn get_unique(conn: &mut Self::ConnectionType) -> CryptoKeystoreResult<Option<Self>>;

    /// Set (or replace) this unique entity into the database.
    async fn set_unique(&self, tx: &Self::Transaction) -> CryptoKeystoreResult<()>;

    /// Returns whether or not the database contains an instance of this unique entity.
    async fn exists(conn: &mut Self::ConnectionType) -> CryptoKeystoreResult<bool>;
}

#[cfg_attr(target_family = "wasm", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_family = "wasm"), async_trait::async_trait)]
impl<'a, E> UniqueEntityExt<'a> for E
where
    E: UniqueEntity + EntityTransactionExt<'a> + Sync,
    <E as EntityTransactionExt<'a>>::Transaction: Sync,
{
    /// Get this unique entity from the database.
    async fn get_unique(conn: &mut Self::ConnectionType) -> CryptoKeystoreResult<Option<Self>> {
        Self::get(conn, &Self::KEY).await
    }

    /// Set (or replace) this unique entity into the database.
    async fn set_unique(&self, tx: &Self::Transaction) -> CryptoKeystoreResult<()> {
        self.save(tx).await
    }

    /// Returns whether or not the database contains an instance of this unique entity.
    async fn exists(conn: &mut Self::ConnectionType) -> CryptoKeystoreResult<bool> {
        <Self as Entity>::count(conn).await.map(|count| count > 0)
    }
}
