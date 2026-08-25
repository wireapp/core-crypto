use rusqlite::{Connection, OptionalExtension, Row, ToSql, Transaction};

use crate::{CryptoKeystoreResult, traits::Entity};

/// Helper to perform an SQL query to get an entity by its primary key
///
/// This function prepares and caches a statement of the form `SELECT * FROM table_name WHERE id = ?`.
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
    E: Entity,
    FromRow: FnOnce(&Row<'_>) -> rusqlite::Result<E>,
{
    let mut statement = conn.prepare_cached(&format!(
        "SELECT * FROM {table_name} WHERE {primary_key_column_name} = ?",
        table_name = E::TABLE_NAME
    ))?;
    statement
        .query_row([primary_key], from_row)
        .optional()
        .map_err(Into::into)
}

/// Helper to perform an SQL query to count these entities in the database.
///
/// This function prepares and caches a statement of the form `SELECT count(*) FROM table_name`.
pub(crate) fn count_helper<E: Entity>(conn: &Connection) -> CryptoKeystoreResult<u32> {
    let mut statement = conn.prepare_cached(&format!(
        "SELECT count(*) FROM {table_name}",
        table_name = E::TABLE_NAME
    ))?;
    statement.query_one([], |row| row.get(0)).map_err(Into::into)
}

/// Helper to perform an SQL query to load all entities from the database.
///
/// This function prepares and caches a statement of the form `SELECT * FROM table_name`.
///
/// You need to provide a row-mapping function. This function gets access to a `row` instance containing all
/// fields known to the database. You can retrieve any of them by using `row.get("my_field")?`.
///
/// Your `from_row` implementation should ideally just need to map the database fields to an appropriate struct,
/// but if it absolutely must handle errors, consider mapping them to [`rusqlite::Error::UserFunctionError`].
pub(crate) fn load_all_helper<E, FromRow>(conn: &Connection, from_row: FromRow) -> CryptoKeystoreResult<Vec<E>>
where
    E: Entity,
    FromRow: FnMut(&Row<'_>) -> rusqlite::Result<E>,
{
    let mut statement = conn.prepare_cached(&format!("SELECT * FROM {table_name}", table_name = E::TABLE_NAME))?;
    statement
        .query_map([], from_row)?
        .collect::<Result<_, _>>()
        .map_err(Into::into)
}

/// Helper to perform an SQL query to delete an entity from the database.
///
/// This function prepares and caches a statement of the form `DELETE FROM table_name WHERE id = ?`.
/// You need to provide the primary key's column name and the actual primary key.
///
/// Returns `true` if at least one entity was deleted, or `false` if the id was not found in the database.
pub(crate) fn delete_helper<E: Entity>(
    tx: &Transaction<'_>,
    primary_key_column_name: &str,
    primary_key: impl ToSql,
) -> CryptoKeystoreResult<bool> {
    let mut statement = tx.prepare_cached(&format!(
        "DELETE FROM {table_name} WHERE {primary_key_column_name} = ?",
        table_name = E::TABLE_NAME,
    ))?;
    let updated = statement.execute([primary_key])?;
    Ok(updated > 0)
}

/// Helper to delete an entity by its primary key.
///
/// This function prepares and caches a statement of the form `DELETE FROM table_name WHERE key_part_1 = ? AND
/// key_part_2 = ?`. The primary-key column names and corresponding parameter values must be provided in the same order.
/// Both simple and composite primary keys are supported.
///
/// Returns the number of rows affected
pub(crate) fn delete_helper_composite_key<E>(
    conn: &Connection,
    primary_key_column_names: &[&str],
    primary_key: impl Params,
) -> CryptoKeystoreResult<u32>
where
    E: Entity,
{
    debug_assert!(
        !primary_key_column_names.is_empty(),
        "a primary key must contain at least one column"
    );

    let predicates = primary_key_column_names
        .iter()
        .map(|column| format!("{column} = ?"))
        .collect::<Vec<_>>()
        .join(" AND ");

    let sql = format!(
        "DELETE FROM {table_name} WHERE {predicates}",
        table_name = E::TABLE_NAME,
    );

    conn.prepare_cached(&sql)?
        .execute(primary_key)
        .map(|count| count.try_into().unwrap_or(u32::MAX))
        .map_err(Into::into)
}
