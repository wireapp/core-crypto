use rusqlite::{Connection, OptionalExtension as _, ToSql, Transaction, params};

use crate::{
    CryptoKeystoreResult,
    entities::helpers::{count_helper, count_helper_tx, delete_helper, load_all_helper},
    traits::{PrimaryKey, UnifiedEntity, entity_database_mutation::UnifiedEntityDatabaseMutation},
    transaction::dynamic_dispatch,
};

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
pub trait UnifiedUniqueEntityImplementationHelper {
    /// Table name for this entity.
    const COLLECTION_NAME: &str;
    fn new(content: Vec<u8>) -> Self;
    fn content(&self) -> &[u8];
}

// unfortunately we have to implement this trait twice, with nearly-identical but distinct bounds

#[cfg(target_os = "unknown")]
impl<T> UnifiedUniqueEntity for T
where
    T: UnifiedEntity + UnifiedUniqueEntityImplementationHelper + PrimaryKey<PrimaryKey = u32>,
{
    const KEY: u32 = 0;
}

#[cfg(not(target_os = "unknown"))]
impl<T> UnifiedUniqueEntity for T
where
    T: UnifiedEntity + UnifiedUniqueEntityImplementationHelper + PrimaryKey<PrimaryKey = u64>,
{
    const KEY: u64 = 0;
}

impl<T> PrimaryKey for T
where
    T: UnifiedUniqueEntityImplementationHelper,
{
    // The old keystore trait used usize as the primary key type, but that would vary
    // in width across various implementations and so is intentionally not a `KeyType`.
    // So we distinguish betwen `u32` and `u64` according to whether or not we're on wasm.
    #[cfg(target_os = "unknown")]
    type PrimaryKey = u32;
    #[cfg(not(target_os = "unknown"))]
    type PrimaryKey = u64;

    fn primary_key(&self) -> Self::PrimaryKey {
        Self::KEY
    }
}

/// A unique entity can appear either 0 or 1 times in the database.
pub trait UnifiedUniqueEntity: PrimaryKey {
    /// The id used as they key when storing this entity in a KV store.
    const KEY: Self::PrimaryKey;
}

/// Unique entities get some convenience methods implemented automatically.
pub trait UnifiedUniqueEntityExt: UnifiedUniqueEntity + UnifiedEntityDatabaseMutation {
    /// Get this unique entity from the database.
    fn get_unique(conn: &Connection) -> CryptoKeystoreResult<Option<Self>>;

    /// Set this unique entity into the database, replacing it if it already exists.
    ///
    /// Returns `true` if the entity previously existed and was replaced, or
    /// `false` if it was not removed and this was a pure insertion.
    fn set_and_replace(&self, tx: &Transaction) -> CryptoKeystoreResult<bool>;

    /// Set this unique entity into the database if it does not already exist.
    ///
    /// Returns `true` if the entity was saved, or `false` if it aborted due to an already-existing entity.
    fn set_if_absent(&self, tx: &Transaction) -> CryptoKeystoreResult<bool>;

    /// Returns whether or not the database contains an instance of this unique entity.
    fn exists(conn: &Connection) -> CryptoKeystoreResult<bool>;
}

impl<E> UnifiedUniqueEntityExt for E
where
    E: UnifiedUniqueEntity + UnifiedEntityDatabaseMutation + Sync,
{
    /// Get this unique entity from the database.
    fn get_unique(conn: &Connection) -> CryptoKeystoreResult<Option<Self>> {
        Self::get(conn, &Self::KEY)
    }

    /// Set this unique entity into the database, replacing it if it already exists.
    ///
    /// Returns `true` if the entity previously existed and was replaced, or
    /// `false` if it was not removed and this was a pure insertion.
    fn set_and_replace(&self, tx: &Transaction) -> CryptoKeystoreResult<bool> {
        let deleted = Self::delete(tx, &Self::KEY)?;
        self.save(tx)?;
        Ok(deleted)
    }

    /// Set this unique entity into the database if it does not already exist.
    ///
    /// Returns `true` if the entity was saved, or `false` if it aborted due to an already-existing entity.
    fn set_if_absent(&self, tx: &Transaction) -> CryptoKeystoreResult<bool> {
        let count = <Self as UnifiedEntityDatabaseMutation>::count(tx)?;
        if count > 0 {
            return Ok(false);
        }
        self.save(tx)?;
        Ok(true)
    }

    /// Returns whether or not the database contains an instance of this unique entity.
    fn exists(conn: &Connection) -> CryptoKeystoreResult<bool> {
        <Self as UnifiedEntity>::count(conn).map(|count| count > 0)
    }
}

impl<T> UnifiedEntity for T
where
    T: PrimaryKey + UnifiedUniqueEntityImplementationHelper,
    <T as PrimaryKey>::PrimaryKey: ToSql,
{
    const COLLECTION_NAME: &'static str = <Self as UnifiedUniqueEntityImplementationHelper>::COLLECTION_NAME;

    fn get(conn: &Connection, key: &Self::PrimaryKey) -> CryptoKeystoreResult<Option<Self>> {
        let mut statement = conn.prepare_cached(&format!(
            "SELECT content FROM {collection_name} WHERE id = ?",
            collection_name = <Self as UnifiedEntity>::COLLECTION_NAME
        ))?;
        statement
            .query_row([key], |row| Ok(Self::new(row.get("content")?)))
            .optional()
            .map_err(Into::into)
    }

    /// Count the number of entities of this type in the database.
    fn count(conn: &Connection) -> CryptoKeystoreResult<u32> {
        count_helper::<Self>(conn)
    }

    /// Retrieve all entities of this type from the database.
    fn load_all(conn: &Connection) -> CryptoKeystoreResult<Vec<Self>> {
        load_all_helper::<Self, _>(conn, |row| Ok(Self::new(row.get("content")?)))
    }
}

impl<T> UnifiedEntityDatabaseMutation for T
where
    T: UnifiedEntity + UnifiedUniqueEntityImplementationHelper + Into<dynamic_dispatch::Entity> + UnifiedUniqueEntity,
    <T as PrimaryKey>::PrimaryKey: ToSql,
{
    type AutoGeneratedFields = ();

    fn save(&self, tx: &Transaction) -> CryptoKeystoreResult<()> {
        let mut stmt = tx.prepare_cached(&format!(
            "INSERT OR REPLACE INTO {collection_name} (id, content) VALUES (?, ?)",
            collection_name = <Self as UnifiedEntity>::COLLECTION_NAME,
        ))?;
        stmt.execute(params![Self::KEY, self.content()])?;
        Ok(())
    }

    fn count(tx: &Transaction) -> CryptoKeystoreResult<u32> {
        count_helper_tx::<Self>(tx)
    }

    fn delete(tx: &Transaction, id: &Self::PrimaryKey) -> CryptoKeystoreResult<bool> {
        delete_helper::<Self>(tx, "id", id)
    }
}
