use rusqlite::{Connection, OptionalExtension, Row, ToSql, Transaction};

use crate::{CryptoKeystoreResult, traits::UnifiedEntity};

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
pub(crate) fn get_helper<E, FromRow>(
    conn: &Connection,
    primary_key_column_name: &str,
    primary_key: impl ToSql,
    from_row: FromRow,
) -> CryptoKeystoreResult<Option<E>>
where
    E: UnifiedEntity,
    FromRow: FnOnce(&Row<'_>) -> rusqlite::Result<E>,
{
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
pub(crate) fn count_helper<E: UnifiedEntity>(conn: &Connection) -> CryptoKeystoreResult<u32> {
    let mut statement = conn.prepare_cached(&format!(
        "SELECT count(*) FROM {collection_name}",
        collection_name = E::COLLECTION_NAME
    ))?;
    statement.query_one([], |row| row.get(0)).map_err(Into::into)
}

/// Helper to perform an SQL query to count these entities in the database.
///
/// This function prepares and caches a statement of the form `SELECT count(*) FROM collection_name`.
pub(crate) fn count_helper_tx<E: UnifiedEntity>(tx: &Transaction<'_>) -> CryptoKeystoreResult<u32> {
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
pub(crate) fn load_all_helper<E, FromRow>(conn: &Connection, from_row: FromRow) -> CryptoKeystoreResult<Vec<E>>
where
    E: UnifiedEntity,
    FromRow: FnMut(&Row<'_>) -> rusqlite::Result<E>,
{
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
pub(crate) fn delete_helper<E: UnifiedEntity>(
    tx: &Transaction<'_>,
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
