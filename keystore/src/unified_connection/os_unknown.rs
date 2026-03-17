//! This module is compiled only when `target_os = "unknown"`.
//!
//! This gives us a place to put idb-specific items.

use async_trait::async_trait;
use rusqlite::Connection;
use sqlite_wasm_rs::WasmOsCallback;
use sqlite_wasm_vfs::relaxed_idb::{self, RelaxedIdbCfgBuilder, RelaxedIdbUtil};

use crate::{CryptoKeystoreError, CryptoKeystoreResult, DatabaseKey};

const VFS_NAME: &str = "multipleciphers-relaxed-idb";

/// Get the VFS utility by reinstalling the VFS
// note: `RelaxedIdbCfg` sets values including the name, which gets used as the IDB database name
async fn get_vfs_util() -> CryptoKeystoreResult<RelaxedIdbUtil> {
    // the virtual file system is named `core-crypto` no matter what databases get contained within it
    // this is the name of the indexeddb database
    // internally, items in this VFS get named with the name of the database as well as their offset
    let cfg = RelaxedIdbCfgBuilder::new().vfs_name("core-crypto").build();
    relaxed_idb::install::<WasmOsCallback>(&cfg, false)
        .await
        .map_err(CryptoKeystoreError::relaxed_idb("installing relaxed-idb vfs"))
}

/// Open the encrypted database at the specified location, creating the database if necessary.
///
/// Encryption: if the database exists, it is assumed to be already encrypted, and decrypted with the provided key.
/// If it does not yet exist, the provided key is set.
///
/// Does not migrate the database.
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
        VFS_NAME,
    )?;

    if already_exists {
        super::encryption::decrypt(&mut conn, key)?;
    } else {
        super::encryption::rekey(&mut conn, key)?;
    }

    Ok((conn, vfs_util))
}

#[derive(derive_more::Debug, derive_more::Deref, derive_more::DerefMut)]
#[debug("RelaxedIdbUtil")]
pub(super) struct FsAbstraction(RelaxedIdbUtil);

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
