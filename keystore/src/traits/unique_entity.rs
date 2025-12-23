use async_trait::async_trait;
#[cfg(not(target_family = "wasm"))]
use rusqlite::{OptionalExtension as _, ToSql, params};
#[cfg(target_family = "wasm")]
use serde::de::DeserializeOwned;

#[cfg(not(target_family = "wasm"))]
use crate::entities::{count_helper, count_helper_tx, delete_helper, load_all_helper};
#[cfg(target_family = "wasm")]
use crate::traits::{Decryptable, Decrypting, Encrypting, KeyType as _};
use crate::{
    CryptoKeystoreResult,
    connection::{KeystoreDatabaseConnection, TransactionWrapper},
    traits::{Entity, EntityBase, PrimaryKey, entity_database_mutation::EntityDatabaseMutation},
};

/// A unique entity can appear either 0 or 1 times in the database.
pub trait UniqueEntity:
    EntityBase<ConnectionType = crate::connection::KeystoreDatabaseConnection> + PrimaryKey
{
    /// The id used as they key when storing this entity in a KV store.
    const KEY: Self::PrimaryKey;
}

/// Unique entities get some convenience methods implemented automatically.
#[cfg_attr(target_family = "wasm", async_trait(?Send))]
#[cfg_attr(not(target_family = "wasm"), async_trait)]
pub trait UniqueEntityExt<'a>: UniqueEntity + EntityDatabaseMutation<'a> {
    /// Get this unique entity from the database.
    async fn get_unique(conn: &mut Self::ConnectionType) -> CryptoKeystoreResult<Option<Self>>;

    /// Set this unique entity into the database, replacing it if it already exists.
    ///
    /// Returns `true` if the entity previously existed and was replaced, or
    /// `false` if it was not removed and this was a pure insertion.
    async fn set_and_replace(&'a self, tx: &Self::Transaction) -> CryptoKeystoreResult<bool>;

    /// Set this unique entity into the database if it does not already exist.
    ///
    /// Returns `true` if the entity was saved, or `false` if it aborted due to an already-existing entity.
    async fn set_if_absent(&'a self, tx: &Self::Transaction) -> CryptoKeystoreResult<bool>;

    /// Returns whether or not the database contains an instance of this unique entity.
    async fn exists(conn: &mut Self::ConnectionType) -> CryptoKeystoreResult<bool>;
}

// unfortunately we have to implement this trait twice, with nearly-identical but distinct bounds

#[cfg(target_family = "wasm")]
#[async_trait(?Send)]
impl<'a, E> UniqueEntityExt<'a> for E
where
    E: UniqueEntity + EntityDatabaseMutation<'a> + Sync,
{
    /// Get this unique entity from the database.
    async fn get_unique(conn: &mut Self::ConnectionType) -> CryptoKeystoreResult<Option<Self>> {
        Self::get(conn, &Self::KEY).await
    }

    /// Set this unique entity into the database, replacing it if it already exists.
    ///
    /// Returns `true` if the entity previously existed and was replaced, or
    /// `false` if it was not removed and this was a pure insertion.
    async fn set_and_replace(&'a self, tx: &Self::Transaction) -> CryptoKeystoreResult<bool> {
        let deleted = Self::delete(tx, &Self::KEY).await?;
        self.save(tx).await?;
        Ok(deleted)
    }

    /// Set this unique entity into the database if it does not already exist.
    ///
    /// Returns `true` if the entity was saved, or `false` if it aborted due to an already-existing entity.
    async fn set_if_absent(&'a self, tx: &Self::Transaction) -> CryptoKeystoreResult<bool> {
        let count = <Self as EntityDatabaseMutation>::count(tx).await?;
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

#[cfg(not(target_family = "wasm"))]
#[async_trait]
impl<'a, E> UniqueEntityExt<'a> for E
where
    E: UniqueEntity + EntityDatabaseMutation<'a> + Sync,
    <E as EntityDatabaseMutation<'a>>::Transaction: Sync,
{
    /// Get this unique entity from the database.
    async fn get_unique(conn: &mut Self::ConnectionType) -> CryptoKeystoreResult<Option<Self>> {
        Self::get(conn, &Self::KEY).await
    }

    /// Set this unique entity into the database, replacing it if it already exists.
    ///
    /// Returns `true` if the entity previously existed and was replaced, or
    /// `false` if it was not removed and this was a pure insertion.
    async fn set_and_replace(&'a self, tx: &Self::Transaction) -> CryptoKeystoreResult<bool> {
        let deleted = Self::delete(tx, &Self::KEY).await?;
        self.save(tx).await?;
        Ok(deleted)
    }

    /// Set this unique entity into the database if it does not already exist.
    ///
    /// Returns `true` if the entity was saved, or `false` if it aborted due to an already-existing entity.
    async fn set_if_absent(&'a self, tx: &Self::Transaction) -> CryptoKeystoreResult<bool> {
        let count = <Self as EntityDatabaseMutation>::count(tx).await?;
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

/// Unique entity implementation/migration helper.
///
/// The old `trait UniqueEntity` required two methods:
///
/// - `fn new(content: Vec<u8>) -> Self;`
/// - `fn content(&self) -> &[u8];`
///
/// It then provided a bunch of default methods.
///
/// The whole structure of the traits has changed, now.
/// But we can stil offer that same kind of convenience, and replicate those defaults.
///
/// If you implement this trait, you get the following traits auto-implemented:
///
/// - `PrimaryKey`
/// - `UniqueEntity`
/// - `Entity`
/// - `EntityDatabaseMutation`
///
/// ## Warning
///
/// If your old `UniqueEntity` implementation defined anything other than the two required methods,
/// you mut implement these traits manually to preserve the existing behaviors. Otherwise the
/// behaviors will change!
pub trait UniqueEntityImplementationHelper {
    fn new(content: Vec<u8>) -> Self;
    fn content(&self) -> &[u8];
}

impl<T> PrimaryKey for T
where
    T: EntityBase<ConnectionType = KeystoreDatabaseConnection> + UniqueEntityImplementationHelper,
{
    // The old keystore trait used usize as the primary key type, but that would vary
    // in width across various implementations and so is intentionally not a `KeyType`.
    // So we distinguish betwen `u32` and `u64` according to whether or not we're on wasm.
    #[cfg(target_family = "wasm")]
    type PrimaryKey = u32;
    #[cfg(not(target_family = "wasm"))]
    type PrimaryKey = u64;

    fn primary_key(&self) -> Self::PrimaryKey {
        Self::KEY
    }
}

#[cfg(target_family = "wasm")]
impl<T> UniqueEntity for T
where
    T: EntityBase<ConnectionType = crate::connection::KeystoreDatabaseConnection>
        + UniqueEntityImplementationHelper
        + PrimaryKey<PrimaryKey = u32>,
{
    const KEY: u32 = 0;
}

#[cfg(target_family = "wasm")]
#[async_trait(?Send)]
impl<T> Entity for T
where
    T: EntityBase<ConnectionType = crate::connection::KeystoreDatabaseConnection>
        + UniqueEntityImplementationHelper
        + UniqueEntity
        + Decryptable<'static>,
    <T as Decryptable<'static>>::DecryptableFrom: DeserializeOwned,
{
    async fn get(conn: &mut Self::ConnectionType, key: &Self::PrimaryKey) -> CryptoKeystoreResult<Option<Self>> {
        conn.storage().new_get(key.bytes().as_ref()).await
    }

    /// Count the number of entities of this type in the database.
    async fn count(conn: &mut Self::ConnectionType) -> CryptoKeystoreResult<u32> {
        conn.storage().new_count::<Self>().await
    }

    /// Retrieve all entities of this type from the database.
    async fn load_all(conn: &mut Self::ConnectionType) -> CryptoKeystoreResult<Vec<Self>> {
        conn.storage().new_get_all().await
    }
}

#[cfg(target_family = "wasm")]
#[async_trait(?Send)]
impl<'a, T> EntityDatabaseMutation<'a> for T
where
    T: EntityBase<ConnectionType = crate::connection::KeystoreDatabaseConnection, AutoGeneratedFields = ()>
        + UniqueEntityImplementationHelper
        + Entity<ConnectionType = crate::connection::KeystoreDatabaseConnection>
        + Encrypting<'a>
        + Sync,
{
    type Transaction = TransactionWrapper<'a>;

    async fn save(&'a self, tx: &Self::Transaction) -> CryptoKeystoreResult<()> {
        tx.new_save(self).await
    }

    async fn count(tx: &Self::Transaction) -> CryptoKeystoreResult<u32> {
        tx.new_count::<Self>().await
    }

    async fn delete(tx: &Self::Transaction, id: &Self::PrimaryKey) -> CryptoKeystoreResult<bool> {
        tx.new_delete::<Self>(id.bytes().as_ref()).await
    }
}

#[cfg(not(target_family = "wasm"))]
impl<T> UniqueEntity for T
where
    T: EntityBase<ConnectionType = crate::connection::KeystoreDatabaseConnection>
        + UniqueEntityImplementationHelper
        + PrimaryKey<PrimaryKey = u64>,
{
    const KEY: u64 = 0;
}

#[cfg(not(target_family = "wasm"))]
#[async_trait]
impl<T> Entity for T
where
    T: EntityBase<ConnectionType = crate::connection::KeystoreDatabaseConnection>
        + PrimaryKey
        + UniqueEntityImplementationHelper,
    <T as PrimaryKey>::PrimaryKey: ToSql,
{
    async fn get(conn: &mut Self::ConnectionType, key: &Self::PrimaryKey) -> CryptoKeystoreResult<Option<Self>> {
        let conn = conn.conn().await;
        let mut statement = conn.prepare_cached(&format!(
            "SELECT content FROM {collection_name} WHERE id = ?",
            collection_name = Self::COLLECTION_NAME
        ))?;
        statement
            .query_row([key], |row| Ok(Self::new(row.get("content")?)))
            .optional()
            .map_err(Into::into)
    }

    /// Count the number of entities of this type in the database.
    async fn count(conn: &mut Self::ConnectionType) -> CryptoKeystoreResult<u32> {
        count_helper::<Self>(conn).await
    }

    /// Retrieve all entities of this type from the database.
    async fn load_all(conn: &mut Self::ConnectionType) -> CryptoKeystoreResult<Vec<Self>> {
        load_all_helper::<Self, _>(conn, |row| Ok(Self::new(row.get("content")?))).await
    }
}

#[cfg(not(target_family = "wasm"))]
#[async_trait]
impl<'a, T> EntityDatabaseMutation<'a> for T
where
    T: EntityBase<ConnectionType = crate::connection::KeystoreDatabaseConnection, AutoGeneratedFields = ()>
        + UniqueEntity
        + UniqueEntityImplementationHelper
        + Sync,
    <T as PrimaryKey>::PrimaryKey: ToSql,
{
    type Transaction = TransactionWrapper<'a>;

    async fn save(&'a self, tx: &Self::Transaction) -> CryptoKeystoreResult<()> {
        let mut stmt = tx.prepare_cached(&format!(
            "INSERT OR REPLACE INTO {collection_name} (id, content) VALUES (?, ?)",
            collection_name = Self::COLLECTION_NAME,
        ))?;
        stmt.execute(params![Self::KEY, self.content()])?;
        Ok(())
    }

    async fn count(tx: &Self::Transaction) -> CryptoKeystoreResult<u32> {
        count_helper_tx::<Self>(tx).await
    }

    async fn delete(tx: &Self::Transaction, id: &Self::PrimaryKey) -> CryptoKeystoreResult<bool> {
        delete_helper::<Self>(tx, "id", id).await
    }
}
