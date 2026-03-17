//! Migration of data from the legacy IndexedDB-based storage to the unified rusqlite connection.
//!
//! On WASM, this is called during [`super::Database::open`] to detect and migrate legacy data
//! before the new connection is initialised.

use idb::Factory;
use rusqlite::{Connection, OptionalExtension as _};

use crate::{
    CryptoKeystoreResult, DatabaseKey,
    connection::{DatabaseConnection as _, KeystoreDatabaseConnection},
    unified_connection::migrations::MigrationTarget,
};

/// Returns `true` if a legacy IndexedDB database with the given name exists and contains data.
///
/// A freshly-created (empty) IDB database always has version 1; any version greater than 1
/// indicates that the legacy migration sequence has been applied and there may be data present.
pub async fn legacy_idb_exists(name: &str) -> bool {
    let Ok(factory) = Factory::new() else {
        return false;
    };
    let Ok(req) = factory.open(name, None) else {
        return false;
    };
    let Ok(db) = req.await else {
        return false;
    };
    let version = db.version().unwrap_or(0);
    db.close();
    version > 1
}

/// Delete the legacy IndexedDB database with the given name.
///
/// This is exposed publicly so that callers can retry deletion independently if it fails during
/// [`maybe_migrate`] (e.g. after a crash between a successful data copy and a failed cleanup).
pub async fn delete_legacy_idb(name: &str) -> CryptoKeystoreResult<()> {
    let factory = Factory::new()?;
    factory.delete(name)?.await?;
    Ok(())
}

/// If a legacy IDB database exists at `name`, migrate all its data into the new connection
/// stored in the VFS identified by `vfs_name`, then delete the legacy IDB.
///
/// Precondition: `new_conn` has not yet had migrations applied, but has been decrypted.
///
/// This is a no-op when:
/// - the unified rusqlite database already exists (already migrated or native platform), or
/// - no legacy IDB database exists at `name` (fresh install).
pub(super) async fn maybe_migrate(
    name: &str,
    database_key: &DatabaseKey,
    new_conn: &mut Connection,
) -> CryptoKeystoreResult<()> {
    /// This SQL database version corresponds to the final IDB version,
    /// so is what we need to perform the migration from IDB
    const SQL_DATABASE_VERSION_AS_OF_FINAL_IDB_VERSION: u16 = 22;

    if !legacy_idb_exists(name).await {
        return Ok(());
    }
    let version = new_conn
        .query_row("PRAGMA user_version;", [], |row| row.get::<_, i32>(0))
        .optional()?;
    if version.is_some_and(|version| version != 0) {
        // a migration has been applied, so the rusqlite databse exists, so we're done
        return Ok(());
    }

    // open the legacy IDB, running all IDB migrations (v0 → v11) in the process.
    let legacy_conn = KeystoreDatabaseConnection::open(name, database_key).await?;

    // migrate the new connection to the version corresponding to the final IDB migration version
    super::migrations::run_migrations(
        new_conn,
        MigrationTarget::Version(SQL_DATABASE_VERSION_AS_OF_FINAL_IDB_VERSION),
    )?;

    todo!("IDB -> rusqlite data migration not yet implemented")
}
