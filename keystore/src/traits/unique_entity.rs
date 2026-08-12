use rusqlite::{Connection, OptionalExtension as _, ToSql, Transaction, params};

use crate::{
    CryptoKeystoreResult,
    entities::helpers::{count_helper, delete_helper, load_all_helper},
    traits::{Entity, PrimaryKey, entity_database_mutation::EntityDatabaseMutation},
};

/// Unique entity implementation/migration helper.
///
/// Few unique entities actually care about what key gets used; it's arbitrary, imposed
/// only by the requirement that an [`Entity`] has a [`PrimaryKey`]. Really they only need
/// to know what table name to use, and how to serialize/deserialize. For reasons of
/// historical compatibility we express the serialization requirements in terms of inline
/// methods here instead of a trait implementation.
///
/// If you implement this trait, you get the following traits auto-implemented:
///
/// - `PrimaryKey`
/// - `UniqueEntity`
/// - `Entity`
/// - `EntityDatabaseMutation`
pub trait UniqueEntityImplementationHelper {
    /// Table name for this entity.
    const TABLE_NAME: &str;
    fn new(content: Vec<u8>) -> Self;
    fn content(&self) -> &[u8];
}

impl<T> UniqueEntity for T
where
    T: Entity + UniqueEntityImplementationHelper + PrimaryKey<PrimaryKey = u32>,
{
    const KEY: u32 = 0;
}

impl<T> PrimaryKey for T
where
    T: UniqueEntityImplementationHelper,
{
    type PrimaryKey = u32;

    fn primary_key(&self) -> Self::PrimaryKey {
        Self::KEY
    }
}

/// A unique entity can appear either 0 or 1 times in the database.
pub trait UniqueEntity: PrimaryKey {
    /// The id used as the key when storing this entity in a KV store.
    const KEY: Self::PrimaryKey;
}

/// Unique entities get some convenience methods implemented automatically.
pub trait UniqueEntityExt: UniqueEntity + EntityDatabaseMutation {
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

impl<E> UniqueEntityExt for E
where
    E: UniqueEntity + EntityDatabaseMutation + Sync,
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
        if Self::exists(tx)? {
            return Ok(false);
        }
        self.save(tx)?;
        Ok(true)
    }

    /// Returns whether or not the database contains an instance of this unique entity.
    fn exists(conn: &Connection) -> CryptoKeystoreResult<bool> {
        Self::count(conn).map(|count| count > 0)
    }
}

impl<T> Entity for T
where
    T: PrimaryKey + UniqueEntityImplementationHelper,
    <T as PrimaryKey>::PrimaryKey: ToSql,
{
    const TABLE_NAME: &'static str = <Self as UniqueEntityImplementationHelper>::TABLE_NAME;

    fn get(conn: &Connection, key: &Self::PrimaryKey) -> CryptoKeystoreResult<Option<Self>> {
        let mut statement = conn.prepare_cached(&format!(
            "SELECT content FROM {table_name} WHERE id = ?",
            table_name = <Self as Entity>::TABLE_NAME
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

impl<T> EntityDatabaseMutation for T
where
    T: Entity + UniqueEntityImplementationHelper + UniqueEntity,
    <T as PrimaryKey>::PrimaryKey: ToSql,
{
    type AutoGeneratedFields = ();

    fn save(&self, tx: &Transaction) -> CryptoKeystoreResult<()> {
        let mut stmt = tx.prepare_cached(&format!(
            "INSERT OR REPLACE INTO {table_name} (id, content) VALUES (?, ?)",
            table_name = <Self as Entity>::TABLE_NAME,
        ))?;
        stmt.execute(params![Self::KEY, self.content()])?;
        Ok(())
    }

    fn delete(tx: &Transaction, id: &Self::PrimaryKey) -> CryptoKeystoreResult<bool> {
        delete_helper::<Self>(tx, "id", id)
    }
}
