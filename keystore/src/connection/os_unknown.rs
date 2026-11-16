//! This module is compiled only when `target_os = "unknown"`.
//!
//! Databases live in OPFS, in the `opfs-sahpool` VFS provided by `sqlite-wasm-vfs`.

use async_trait::async_trait;
use sqlite_wasm_rs::{WasmOsCallback, vfs::VfsFilesManager as _};
use sqlite_wasm_vfs::sahpool::{OpfsSAHError, OpfsSAHPoolCfgBuilder, OpfsSAHPoolUtil};

use super::{ManagedConnection, legacy_opfs};
use crate::{CryptoKeystoreError, CryptoKeystoreResult, DatabaseKey};

/// The pool's directory in the OPFS root.
///
/// Can't use `core-crypto`: that's where CoreCrypto 11 kept its databases.
const POOL_DIRECTORY: &str = "core-crypto-sahpool";

const VFS_NAME: &str = POOL_DIRECTORY;

/// Free slots to make sure of before opening a database.
///
/// Every file SQLite opens takes a slot: the database, its WAL and rollback journal, and temporary
/// files that some queries may create. This number may not be as low as possible, but six should be
/// sufficient.
const SLOT_HEADROOM: usize = 6;

/// What SQLite appends to a database's name to name its WAL and rollback journal, after the empty suffix of the
/// database itself.
pub(super) const FILE_SUFFIXES: [&str; 3] = ["", "-wal", "-journal"];

/// Install the pool, or get the one already installed in this worker.
pub(super) async fn pool() -> CryptoKeystoreResult<OpfsSAHPoolUtil> {
    let config = OpfsSAHPoolCfgBuilder::new()
        .vfs_name(VFS_NAME)
        .directory(POOL_DIRECTORY)
        .build();
    // Installs or gets an already-existing pool. In the latter case, this can be a paused pool or a
    // pool that needs recovery (which will surface only after)
    let pool = sqlite_wasm_vfs::sahpool::install::<WasmOsCallback>(&config, false)
        .await
        .map_err(CryptoKeystoreError::opfs("installing the OPFS pool"))?;

    // A pool is left paused after a previous I/O operation failed.
    // pool.len() probes whether the pool's needs_recovery flag is set. Both states are fixed by
    // `.pause()`/`.resume()`.
    if pool.is_paused() || matches!(pool.len(), Err(OpfsSAHError::NeedsRecovery)) {
        log::warn!("recovering the OPFS pool after an I/O error");
        pool.pause()
            .map_err(CryptoKeystoreError::opfs("recovering the OPFS pool"))?;
        pool.resume()
            .await
            .map_err(CryptoKeystoreError::opfs("recovering the OPFS pool"))?;
    }
    Ok(pool)
}

/// Reject names CoreCrypto 11 rejected, so that every valid name maps to a legacy OPFS path.
///
/// CoreCrypto 11 read `/` as a directory separator. An element can't be blank, `.`, or `..`.
fn validate_name(name: &str) -> CryptoKeystoreResult<()> {
    if name.split('/').any(|element| matches!(element, "" | "." | "..")) {
        return Err(CryptoKeystoreError::InvalidDatabaseName(name.to_owned()));
    }
    Ok(())
}

/// Open the encrypted database at the specified location, creating the database if necessary.
///
/// Encryption: if the database exists, it is assumed to be already encrypted, and decrypted with the provided key.
/// If it does not yet exist, the provided key is set.
///
/// Migration: moves a CoreCrypto 11 database at the same location into the pool. Might partially migrate the
/// database, if it detects that a legacy IDB database exists whose data has not yet been imported. A final
/// migration to latest version will be necessary!
pub(super) async fn open(name: &str, key: &DatabaseKey) -> CryptoKeystoreResult<(ManagedConnection, FsAbstraction)> {
    validate_name(name)?;
    super::idb_migration::reject_core_crypto_10_database(name).await?;

    let pool = pool().await?;
    // Before the migration, which takes one of these slots for the database it imports.
    let slots = pool
        .len()
        .map_err(CryptoKeystoreError::opfs("counting files in the OPFS pool"))?;
    pool.ensure_capacity(slots + SLOT_HEADROOM)
        .await
        .map_err(CryptoKeystoreError::opfs("growing the OPFS pool"))?;
    legacy_opfs::migrate(&pool, name, key).await?;

    let already_exists = pool
        .contains(name)
        .map_err(CryptoKeystoreError::opfs("checking database existence"))?;
    // the flags we use here are equivalent to the defaults, except we don't engage uri handling
    // https://docs.rs/rusqlite/latest/rusqlite/struct.Connection.html#method.open
    let mut conn = ManagedConnection::from(rusqlite::Connection::open_with_flags_and_vfs(
        name,
        rusqlite::OpenFlags::SQLITE_OPEN_CREATE
            | rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE
            | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
        VFS_NAME,
    )?);

    // Set before encryption, schema reads, or reopening a database already in WAL mode.
    // The pool has no shared memory, so WAL needs exclusive locking.
    conn.pragma_update(None, "locking_mode", "EXCLUSIVE")?;

    if already_exists {
        super::encryption::decrypt(&mut conn, key)?;
    } else {
        super::encryption::key(&mut conn, key)?;
    }

    // Not gated on `already_exists`: the file also exists after an import which failed or was interrupted,
    // and the import must run again in that case. `maybe_migrate` decides from the database's own state.
    super::idb_migration::maybe_migrate(name, key, &mut conn).await?;

    Ok((conn, FsAbstraction))
}

#[derive(Debug)]
pub(super) struct FsAbstraction;

#[async_trait(?Send)]
impl super::Filesystem for FsAbstraction {
    async fn delete(&self, path: &str) -> CryptoKeystoreResult<()> {
        let pool = pool().await?;
        // SQLite normally removes these on close, but persistent journals may remain.
        for suffix in FILE_SUFFIXES {
            pool.remove(&format!("{path}{suffix}"))
                .map_err(CryptoKeystoreError::opfs("deleting file"))?;
        }
        Ok(())
    }
}

#[cfg(test)]
pub(super) fn unique_name(prefix: &str) -> String {
    format!("{prefix}-{}.db", uuid::Uuid::new_v4())
}

#[cfg(test)]
pub(super) async fn wipe(db: std::sync::Arc<crate::Database>) {
    std::sync::Arc::into_inner(db).unwrap().wipe().await.unwrap();
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use wasm_bindgen_test::wasm_bindgen_test;

    use super::{unique_name, wipe};
    use crate::{Database, DatabaseKey};

    #[wasm_bindgen_test]
    async fn dropping_transaction_and_database_rolls_back_and_closes_before_reopen() {
        let name = unique_name("managed");
        let key = DatabaseKey::generate();
        let db = Database::open(&name, &key).await.unwrap();
        db.conn()
            .await
            .execute_batch("CREATE TABLE cleanup_probe(value INTEGER); INSERT INTO cleanup_probe VALUES (1);")
            .unwrap();
        let tx = db.new_transaction().await.unwrap();
        tx.conn()
            .unwrap()
            .execute("UPDATE cleanup_probe SET value=2", [])
            .unwrap();

        drop(tx);
        drop(db);

        let db = Database::open(&name, &key).await.unwrap();
        assert_eq!(
            db.conn()
                .await
                .query_row("SELECT value FROM cleanup_probe", [], |row| row.get::<_, i64>(0))
                .unwrap(),
            1
        );
        assert_eq!(
            db.conn()
                .await
                .pragma_query_value(None, "journal_mode", |row| row.get::<_, String>(0))
                .unwrap(),
            "wal"
        );
        wipe(db).await;
    }

    #[wasm_bindgen_test]
    async fn rekey_keeps_wal_and_reopens_with_the_new_key() {
        let name = unique_name("rekey");
        let old_key = DatabaseKey::generate();
        let new_key = DatabaseKey::generate();
        let db = Database::open(&name, &old_key).await.unwrap();
        db.conn()
            .await
            .execute_batch("CREATE TABLE rekey_probe(value INTEGER); INSERT INTO rekey_probe VALUES (7)")
            .unwrap();
        db.update_key(&new_key).await.unwrap();
        assert_eq!(
            db.conn()
                .await
                .pragma_query_value(None, "journal_mode", |row| row.get::<_, String>(0))
                .unwrap(),
            "wal"
        );
        Arc::into_inner(db).unwrap().close().await.unwrap();
        assert!(Database::open(&name, &old_key).await.is_err());
        let db = Database::open(&name, &new_key).await.unwrap();
        assert_eq!(
            db.conn()
                .await
                .query_row("SELECT value FROM rekey_probe", [], |row| row.get::<_, i64>(0))
                .unwrap(),
            7
        );
        wipe(db).await;
    }

    #[wasm_bindgen_test]
    async fn dropped_transaction_releases_connection_for_the_next_transaction() {
        let name = unique_name("rollback");
        let db = Database::open(&name, &DatabaseKey::generate()).await.unwrap();
        db.conn()
            .await
            .execute_batch("CREATE TABLE rollback_probe(value INTEGER)")
            .unwrap();
        let tx = db.new_transaction().await.unwrap();
        tx.conn()
            .unwrap()
            .execute("INSERT INTO rollback_probe VALUES (1)", [])
            .unwrap();
        drop(tx);
        let tx = db.new_transaction().await.unwrap();
        assert_eq!(
            tx.conn()
                .unwrap()
                .query_row("SELECT count(*) FROM rollback_probe", [], |row| row.get::<_, i64>(0))
                .unwrap(),
            0
        );
        tx.commit().await.unwrap();
        wipe(db).await;
    }
}
