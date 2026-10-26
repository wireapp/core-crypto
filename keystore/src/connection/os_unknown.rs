//! This module is compiled only when `target_os = "unknown"`.
//!
//! This gives us a place to put OPFS-specific items.

use async_trait::async_trait;
use sqlite_wasm_rs::WasmOsCallback;

use super::{ManagedConnection, SqliteGuard, opfs_vfs};
use crate::{CryptoKeystoreError, CryptoKeystoreResult, DatabaseKey};

const VFS_NAME: &str = "core-crypto";

/// The caller must hold `SqliteGuard`.
pub(super) fn ensure_vfs_installed(guard: &SqliteGuard) -> CryptoKeystoreResult<()> {
    opfs_vfs::install(VFS_NAME, WasmOsCallback, guard).map_err(CryptoKeystoreError::opfs("installing the OPFS VFS"))
}

/// Open the encrypted database at the specified location, creating the database if necessary.
///
/// Encryption: if the database exists, it is assumed to be already encrypted, and decrypted with the provided key.
/// If it does not yet exist, the provided key is set.
///
/// Migration: might partially migrate the database, if it detects that a legacy IDB database exists whose
/// data has not yet been imported. A final migration to latest version will be necessary!
pub(super) async fn open(name: &str, key: &DatabaseKey) -> CryptoKeystoreResult<(ManagedConnection, FsAbstraction)> {
    super::idb_migration::reject_core_crypto_10_database(name).await?;

    let sqlite = SqliteGuard::lock();
    ensure_vfs_installed(&sqlite)?;
    let already_exists = opfs_vfs::contains(name).map_err(CryptoKeystoreError::opfs("checking database existence"))?;
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
    // A second connection to this file cannot acquire its OPFS access handle, so the VFS needs no locking.
    super::encryption::set_pragma_unchecked(&conn, "locking_mode", "EXCLUSIVE")?;

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
        let _sqlite = SqliteGuard::lock();
        // SQLite normally removes these on close, but persistent journals may remain.
        for name in [path.to_owned(), format!("{path}-journal"), format!("{path}-wal")] {
            if let Err(error) = opfs_vfs::delete(&name)
                && error.code() != rsqlite_vfs::VfsErrorCode::IoDeleteNoEntry
            {
                return Err(CryptoKeystoreError::opfs("deleting file")(error));
            }
        }
        Ok(())
    }
}
