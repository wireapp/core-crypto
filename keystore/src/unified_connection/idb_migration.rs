//! Migration of data from the legacy IndexedDB-based storage to the unified rusqlite connection.
//!
//! On WASM, this is called during [`super::Database::open`] to detect and migrate legacy data
//! before the new connection is initialised.

use idb::Factory;

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
