//! This module is compiled only when `target_os = "unknown"`.
//!
//! This gives us a place to put idb-specific items.

use std::sync::LazyLock;

use sqlite_wasm_rs::WasmOsCallback;
use sqlite_wasm_vfs::relaxed_idb::{self, RelaxedIdbCfgBuilder, RelaxedIdbUtil};

use crate::{CryptoKeystoreError, CryptoKeystoreResult, DatabaseKey};

static RUSQLITE_FLAGS: LazyLock<rusqlite::OpenFlags> = LazyLock::new(|| {
    rusqlite::OpenFlags::SQLITE_OPEN_CREATE
        | rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE
        | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX
});
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

/// A database connection
///
/// This delegates to a normal [`rusqlite::Connection`], but also contains the idb
/// utilities which give access to the VFS used to run the sqlite database.
#[derive(derive_more::Debug, derive_more::Deref, derive_more::DerefMut)]
pub(super) struct Connection {
    /// The connection itself
    #[deref]
    #[deref_mut]
    sqlite: rusqlite::Connection,
    /// VFS tools
    //
    // This will be unused until/unless we implement things like database vacuum/download
    #[expect(unused)]
    #[debug("<RelaxedIdbUtil>")]
    vfs_util: RelaxedIdbUtil,
    /// The name of the database
    //
    // This will be unused until/unless we implement things like database vacuum/download
    #[expect(unused)]
    name: String,
}

impl Connection {
    /// Open the encrypted database at the specified location, creating the database if necessary.
    ///
    /// Encryption: if the database exists, it is assumed to be already encrypted, and decrypted with the provided key.
    /// If it does not yet exist, the provided key is set.
    ///
    /// Does not migrate the database.
    pub(super) async fn open(name: &str, key: &DatabaseKey) -> CryptoKeystoreResult<Self> {
        let vfs_util = get_vfs_util().await?;
        let already_exists = vfs_util.exists(name);
        let mut sqlite = rusqlite::Connection::open_with_flags_and_vfs(name, *RUSQLITE_FLAGS, VFS_NAME)?;

        if already_exists {
            super::encryption::decrypt(&mut sqlite, key)?;
        } else {
            super::encryption::rekey(&mut sqlite, key)?;
        }

        Ok(Self {
            vfs_util,
            sqlite,
            name: name.to_owned(),
        })
    }
}
