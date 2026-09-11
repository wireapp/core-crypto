//! This module is compiled only when `target_os = "unknown"`.
//!
//! This gives us a place to put idb-specific items.

use async_trait::async_trait;
use rusqlite::Connection;
use sqlite_wasm_rs::WasmOsCallback;
use sqlite_wasm_vfs::relaxed_idb::{self, RelaxedIdbCfgBuilder, RelaxedIdbUtil};

use crate::{CryptoKeystoreError, CryptoKeystoreResult, DatabaseKey};

// To use sqlite3-multiple-ciphers, you have to prepend the VFS name with `multipleciphers-`.
// This is true even if you use a non-default VFS name.
const VFS_NAME: &str = "core-crypto";
const VFS_NAME_WITH_ENCRYPTION: &str = "multipleciphers-core-crypto";

/// Get the VFS utility by reinstalling the VFS
// note: `RelaxedIdbCfg` sets values including the name, which gets used as the IDB database name
async fn get_vfs_util() -> CryptoKeystoreResult<RelaxedIdbUtil> {
    // the virtual file system is named `core-crypto` no matter what databases get contained within it
    // this is the name of the indexeddb database
    // internally, items in this VFS get named with the name of the database as well as their offset
    let cfg = RelaxedIdbCfgBuilder::new().vfs_name(VFS_NAME).build();
    relaxed_idb::install::<WasmOsCallback>(&cfg, false)
        .await
        .map_err(CryptoKeystoreError::relaxed_idb("installing relaxed-idb vfs"))
}

/// Open the encrypted database at the specified location, creating the database if necessary.
///
/// Encryption: if the database exists, it is assumed to be already encrypted, and decrypted with the provided key.
/// If it does not yet exist, the provided key is set.
///
/// Migration: might partially migrate the database, if it detects that a legacy IDB database exists whose
/// data has not yet been imported. A final migration to latest version will be necessary!
pub(super) async fn open(name: &str, key: &DatabaseKey) -> CryptoKeystoreResult<(Connection, FsAbstraction)> {
    let vfs_util = FsAbstraction(get_vfs_util().await?);
    let already_exists = vfs_util.exists(name);
    // the flags we use here are equivalent to the defaults, except we don't engage uri handling
    // https://docs.rs/rusqlite/latest/rusqlite/struct.Connection.html#method.open
    let mut conn = rusqlite::Connection::open_with_flags_and_vfs(
        name,
        rusqlite::OpenFlags::SQLITE_OPEN_CREATE
            | rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE
            | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
        VFS_NAME_WITH_ENCRYPTION,
    )?;

    if already_exists {
        super::encryption::decrypt(&mut conn, key)?;
    } else {
        super::encryption::rekey(&mut conn, key)?;
    }

    // Not gated on `already_exists`: the file also exists after an import which failed or was interrupted,
    // and the import must run again in that case. `maybe_migrate` decides from the database's own state.
    super::idb_migration::maybe_migrate(name, key, &mut conn, &vfs_util).await?;

    Ok((conn, vfs_util))
}

#[derive(derive_more::Debug, derive_more::Deref, derive_more::DerefMut)]
#[debug("RelaxedIdbUtil")]
pub(super) struct FsAbstraction(RelaxedIdbUtil);

/// A file name no keystore is ever opened under, used only as the target of the no-op deletion in
/// [`FsAbstraction::flush`].
const DURABILITY_BARRIER_FILE: &str = ".core-crypto-durability-barrier";

impl FsAbstraction {
    /// Wait until every write the VFS has queued so far has reached IndexedDB.
    ///
    /// relaxed-idb is relaxed about durability: when SQLite commits, the VFS queues the write of the changed pages
    /// and returns at once, and a worker drains the queue into IndexedDB later. Most of the time that is an
    /// acceptable trade. It is not acceptable at the one point where we are about to destroy the only other copy of
    /// the data, so the import calls this between committing the copy and deleting the legacy database.
    ///
    /// The VFS offers no flush operation, but its queue is strictly ordered and a deletion goes through the same
    /// queue with a completion signal. Deleting a file which does not exist is a no-op, so awaiting one is a
    /// barrier: it resolves only once everything queued before it has landed.
    pub(super) async fn flush(&self) -> CryptoKeystoreResult<()> {
        self.delete_db(DURABILITY_BARRIER_FILE)
            .map_err(CryptoKeystoreError::relaxed_idb("queueing the durability barrier"))?
            .await
            .map_err(CryptoKeystoreError::relaxed_idb(
                "waiting for queued writes to reach IndexedDB",
            ))?;
        Ok(())
    }
}

// SAFETY: so this is a lie, it's not safe.
// But on the other hand we only ever compile this where `target_os = "unknown"`,
// specifically `wasm32-unknown-unknown`, where there is never more than one thread anyway.
// So we can be confident about getting away with it.
unsafe impl Send for FsAbstraction {}

#[async_trait(?Send)]
impl super::Filesystem for FsAbstraction {
    async fn delete(&self, path: &str) -> CryptoKeystoreResult<()> {
        self.delete_db(path)
            .map_err(CryptoKeystoreError::relaxed_idb("preparing file deletion future"))?
            .await
            .map_err(CryptoKeystoreError::relaxed_idb("deleting file"))?;
        Ok(())
    }
}
