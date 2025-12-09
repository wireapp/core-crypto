// Much like the new traits, the items in this module are being added now in expectation of future utility,
// but won't actually be used until it's time to use those new traits.
#![expect(unused)]

mod general;
mod mls;
#[cfg(feature = "proteus-keystore")]
mod proteus;

use rusqlite::{OptionalExtension, Row, ToSql};

pub use self::mls::*;
#[cfg(feature = "proteus-keystore")]
pub use self::proteus::*;
use crate::{
    CryptoKeystoreResult,
    connection::{KeystoreDatabaseConnection, TransactionWrapper},
    traits::Entity,
};

/// Helper to perform an SQL query to get an entity by its primary key
///
/// This function prepares and caches a statement of the form `SELECT * FROM collection_name WHERE id = ?`.
/// You need to provide the primary key's column name and the actual primary key, and a row-mapping function.
///
/// The row-mapping function gets access to a `row` instance containing all fields known to the database. You can
/// retrieve any of them by name by using `row.get("my_field")?`.
///
/// Your `from_row` implementation should ideally just need to map the database fields to an appropriate struct,
/// but if it absolutely must handle errors, consider mapping them to [`rusqlite::Error::UserFunctionError`].
pub(crate) async fn get_helper<E, FromRow>(
    conn: &KeystoreDatabaseConnection,
    primary_key_column_name: &str,
    primary_key: impl ToSql,
    from_row: FromRow,
) -> CryptoKeystoreResult<Option<E>>
where
    E: Entity,
    FromRow: FnOnce(&Row<'_>) -> rusqlite::Result<E>,
{
    let conn = conn.conn().await;
    let mut statement = conn.prepare_cached(&format!(
        "SELECT * FROM {collection_name} WHERE {primary_key_column_name} = ?",
        collection_name = E::COLLECTION_NAME
    ))?;
    statement
        .query_row([primary_key], from_row)
        .optional()
        .map_err(Into::into)
}

/// Helper to perform an SQL query to count these entities in the database.
///
/// This function prepares and caches a statement of the form `SELECT count(*) FROM collection_name`.
pub(crate) async fn count_helper<E: Entity>(conn: &KeystoreDatabaseConnection) -> CryptoKeystoreResult<u32> {
    let conn = conn.conn().await;
    let mut statement = conn.prepare_cached(&format!(
        "SELECT count(*) FROM {collection_name}",
        collection_name = E::COLLECTION_NAME
    ))?;
    statement.query_one([], |row| row.get(0)).map_err(Into::into)
}

/// Helper to perform an SQL query to count these entities in the database.
///
/// This function prepares and caches a statement of the form `SELECT count(*) FROM collection_name`.
pub(crate) async fn count_helper_tx<E: Entity>(tx: &TransactionWrapper<'_>) -> CryptoKeystoreResult<u32> {
    let mut statement = tx.prepare_cached(&format!(
        "SELECT count(*) FROM {collection_name}",
        collection_name = E::COLLECTION_NAME
    ))?;
    statement.query_one([], |row| row.get(0)).map_err(Into::into)
}

/// Helper to perform an SQL query to load all entities from the database.
///
/// This function prepares and caches a statement of the form `SELECT * FROM collection_name`.
///
/// You need to provide a row-mapping function. This function gets access to a `row` instance containing all
/// fields known to the database. You can retrieve any of them by using `row.get("my_field")?`.
///
/// Your `from_row` implementation should ideally just need to map the database fields to an appropriate struct,
/// but if it absolutely must handle errors, consider mapping them to [`rusqlite::Error::UserFunctionError`].
pub(crate) async fn load_all_helper<E, FromRow>(
    conn: &KeystoreDatabaseConnection,
    from_row: FromRow,
) -> CryptoKeystoreResult<Vec<E>>
where
    E: Entity,
    FromRow: FnMut(&Row<'_>) -> rusqlite::Result<E>,
{
    let conn = conn.conn().await;
    let mut statement = conn.prepare_cached(&format!(
        "SELECT * FROM {collection_name}",
        collection_name = E::COLLECTION_NAME
    ))?;
    statement
        .query_map([], from_row)?
        .collect::<Result<_, _>>()
        .map_err(Into::into)
}

/// Helper to perform an SQL query to delete an entity from the database.
///
/// This function prepares and caches a statement of the form `DELETE FROM collection_name WHERE id = ?`.
/// You need to provide the primary key's column name and the actual primary key.
///
/// Returns `true` if at least one entity was deleted, or `false` if the id was not found in the database.
pub(crate) async fn delete_helper<E: Entity>(
    tx: &TransactionWrapper<'_>,
    primary_key_column_name: &str,
    primary_key: impl ToSql,
) -> CryptoKeystoreResult<bool> {
    let mut statement = tx.prepare_cached(&format!(
        "DELETE FROM {collection_name} WHERE {primary_key_column_name} = ?",
        collection_name = E::COLLECTION_NAME,
    ))?;
    let updated = statement.execute([primary_key])?;
    Ok(updated > 0)
}
