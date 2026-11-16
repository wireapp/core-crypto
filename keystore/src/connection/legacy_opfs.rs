//! Moves CoreCrypto 11 databases into the OPFS pool.
//!
//! CoreCrypto 11 kept each database as plain OPFS files under `core-crypto/<name>`, next to its `-wal` and `-journal`
//! files. The pool can only import a main database file, so the legacy files are first put together in memory: the
//! WAL is checkpointed into the main file there, then that file is imported into the pool.
//!
//! The legacy files are deleted only after the import committed. If deleting them fails, or the worker dies first,
//! the next open finds the database in the pool and only retries the deletion.

use std::mem::DropGuard;

use js_sys::Reflect;
use sqlite_wasm_rs::{
    WasmOsCallback,
    vfs::{VfsFilesManager as _, memvfs, transfer::DbTransfer as _},
};
use sqlite_wasm_vfs::sahpool::OpfsSAHPoolUtil;
use wasm_bindgen::{JsCast, JsValue};
use wasm_bindgen_futures::JsFuture;
use web_sys::{
    FileSystemDirectoryHandle, FileSystemFileHandle, FileSystemReadWriteOptions, FileSystemSyncAccessHandle,
    WorkerGlobalScope,
};

use super::os_unknown::FILE_SUFFIXES;
use crate::{CryptoKeystoreError, CryptoKeystoreResult, DatabaseKey};

/// Where CoreCrypto 11 kept its databases, in the OPFS root.
const LEGACY_DIRECTORY: &str = "core-crypto";
/// Prefix of the names the legacy files get in `memvfs` while being put together.
const STAGING_PREFIX: &str = "core-crypto-legacy-opfs/";

fn js_error(context: &'static str) -> impl FnOnce(JsValue) -> CryptoKeystoreError {
    move |value| {
        let get = |key: &str| Reflect::get(&value, &key.into()).ok().and_then(|x| x.as_string());
        let message = format!(
            "OPFS {}: {}",
            get("name").as_deref().unwrap_or("error"),
            get("message").unwrap_or_else(|| format!("{value:?}"))
        );
        CryptoKeystoreError::legacy_opfs(context)(std::io::Error::other(message))
    }
}

fn is_not_found(value: &JsValue) -> bool {
    Reflect::get(value, &"name".into())
        .ok()
        .and_then(|name| name.as_string())
        .is_some_and(|name| name == "NotFoundError")
}

/// Awaits an OPFS lookup, mapping `NotFoundError` to `None`.
async fn lookup<T: JsCast>(promise: js_sys::Promise, context: &'static str) -> CryptoKeystoreResult<Option<T>> {
    match JsFuture::from(promise).await {
        Ok(value) => Ok(Some(value.unchecked_into())),
        Err(error) if is_not_found(&error) => Ok(None),
        Err(error) => Err(js_error(context)(error)),
    }
}

/// Walk down from the OPFS root through `directories`, without creating anything.
///
/// Returns the handles of the root and of every directory on the way, or `None` if any of them doesn't exist.
async fn directory_chain(directories: &[&str]) -> CryptoKeystoreResult<Option<Vec<FileSystemDirectoryHandle>>> {
    let scope: WorkerGlobalScope = js_sys::global()
        .dyn_into()
        .map_err(|global| js_error("finding the worker scope")(global.into()))?;
    let root: FileSystemDirectoryHandle = JsFuture::from(scope.navigator().storage().get_directory())
        .await
        .map_err(js_error("opening the OPFS root"))?
        .unchecked_into();
    let mut chain = vec![root];
    for element in directories {
        let parent = chain.last().expect("the chain starts with the root");
        match lookup(parent.get_directory_handle(element), "opening a legacy OPFS directory").await? {
            Some(child) => chain.push(child),
            None => return Ok(None),
        }
    }
    Ok(Some(chain))
}

/// Walk down from the OPFS root through `directories`, without creating anything.
///
/// Returns the handles of the root, or `None` if any of them doesn't exist.
async fn directory(directories: &[&str]) -> CryptoKeystoreResult<Option<FileSystemDirectoryHandle>> {
    Ok(directory_chain(directories).await?.and_then(|mut chain| chain.pop()))
}

/// The legacy path of database `name`: its directories from the OPFS root, and its file name.
fn legacy_path(name: &str) -> (Vec<&str>, &str) {
    let mut directories = std::iter::once(LEGACY_DIRECTORY)
        .chain(name.split('/'))
        .collect::<Vec<_>>();
    let filename = directories.pop().expect("the name has at least one element");
    (directories, filename)
}

/// Read a whole OPFS file, or `None` if it doesn't exist.
async fn read(directory: &FileSystemDirectoryHandle, name: &str) -> CryptoKeystoreResult<Option<Vec<u8>>> {
    let Some(file) =
        lookup::<FileSystemFileHandle>(directory.get_file_handle(name), "opening a legacy OPFS file").await?
    else {
        return Ok(None);
    };
    let handle: FileSystemSyncAccessHandle = JsFuture::from(file.create_sync_access_handle())
        .await
        .map_err(js_error("opening a legacy OPFS file"))?
        .unchecked_into();
    let result = (|| {
        let size = handle.get_size().map_err(js_error("reading a legacy OPFS file"))? as usize;
        let mut bytes = vec![0; size];
        let options = FileSystemReadWriteOptions::new();
        options.set_at(0.0);
        let count = handle
            .read_with_u8_array_and_options(&mut bytes, &options)
            .map_err(js_error("reading a legacy OPFS file"))? as usize;
        if count != size {
            return Err(CryptoKeystoreError::legacy_opfs("reading a legacy OPFS file")(
                std::io::Error::from(std::io::ErrorKind::UnexpectedEof),
            ));
        }
        Ok(bytes)
    })();
    handle.close();
    result.map(Some)
}

/// Delete the legacy files of `name`, then any directories this left empty.
///
/// Failures are only logged: the database is in the pool already, and the next open tries again.
async fn delete_legacy_files(name: &str) {
    let (mut directories, filename) = legacy_path(name);
    let Ok(Some(mut chain)) = directory_chain(&directories).await else {
        return;
    };
    let parent = chain.pop().expect("the chain starts with the root");
    for suffix in FILE_SUFFIXES {
        let file = format!("{filename}{suffix}");
        if let Err(error) = JsFuture::from(parent.remove_entry(&file)).await
            && !is_not_found(&error)
        {
            log::warn!(file:%; "failed to delete legacy OPFS file: {error:?}");
        }
    }

    // Walk back up, removing directories which are now empty. Removing a directory which isn't empty fails without
    // `recursive`, which ends the walk.
    while let (Some(child), Some(parent)) = (directories.pop(), chain.pop()) {
        if JsFuture::from(parent.remove_entry(child)).await.is_err() {
            return;
        }
    }
}

/// Remove the staging files of `name` from `memvfs`.
fn clear_staging(memvfs: &memvfs::MemVfsUtil, name: &str) {
    for suffix in FILE_SUFFIXES {
        let _ = memvfs.remove(&format!("{name}{suffix}"));
    }
}

/// Put the legacy files together in memory, and return the main database file with the WAL checkpointed into it.
fn checkpoint(
    name: &str,
    key: &DatabaseKey,
    main: Vec<u8>,
    wal: Option<Vec<u8>>,
    journal: Option<Vec<u8>>,
) -> CryptoKeystoreResult<Vec<u8>> {
    // SAFETY: Wasm is single-threaded, so VFS registration is serialized and memvfs stays on this thread.
    let memvfs = unsafe { memvfs::install(WasmOsCallback, false) }
        .map_err(CryptoKeystoreError::legacy_opfs("installing the in-memory VFS"))?;
    let staging = format!("{STAGING_PREFIX}{name}");
    // Leftovers from a run that was interrupted.
    clear_staging(&memvfs, &staging);
    let staging = DropGuard::new(staging, |staging| clear_staging(&memvfs, &staging));

    let import = |suffix: &str, bytes: &[u8]| {
        memvfs
            .import_db_unchecked(&format!("{}{suffix}", *staging), bytes)
            .map_err(CryptoKeystoreError::legacy_opfs("staging a legacy OPFS file"))
    };
    import("", &main)?;
    drop(main);
    if let Some(wal) = wal {
        import("-wal", &wal)?;
    }
    if let Some(journal) = journal {
        import("-journal", &journal)?;
    }

    let mut conn = rusqlite::Connection::open_with_flags_and_vfs(
        &*staging,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
        "memvfs",
    )?;
    // CoreCrypto 11 used exclusive locking, and the WAL can only be read the same way.
    conn.pragma_update(None, "locking_mode", "EXCLUSIVE")?;
    super::encryption::decrypt(&mut conn, key)?;
    // The first read checks the key, and recovers from a hot rollback journal.
    conn.query_row("SELECT count(*) FROM sqlite_master", [], |_| Ok(()))?;
    let busy = conn.query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |row| row.get::<_, i64>(0))?;
    if busy != 0 {
        return Err(CryptoKeystoreError::MigrationFailed(
            "could not checkpoint the legacy OPFS database".into(),
        ));
    }
    conn.close().map_err(|(_conn, error)| error)?;

    memvfs.export_db(&staging).map_err(CryptoKeystoreError::legacy_opfs(
        "exporting the checkpointed legacy database",
    ))
}

/// Move the CoreCrypto 11 database `name` into `pool`, if there is one.
///
/// `pool` must have a free slot for the imported database.
pub(super) async fn migrate(pool: &OpfsSAHPoolUtil, name: &str, key: &DatabaseKey) -> CryptoKeystoreResult<()> {
    let in_pool = pool
        .contains(name)
        .map_err(CryptoKeystoreError::opfs("checking database existence"))?;
    if in_pool {
        // A previous migration may have stopped before deleting the legacy files.
        delete_legacy_files(name).await;
        return Ok(());
    }

    let (directories, filename) = legacy_path(name);
    let Some(parent) = directory(&directories).await? else {
        return Ok(());
    };
    let Some(main) = read(&parent, filename).await? else {
        return Ok(());
    };
    let wal = read(&parent, &format!("{filename}-wal")).await?;
    let journal = read(&parent, &format!("{filename}-journal")).await?;

    log::info!("moving the CoreCrypto 11 database into the OPFS pool");
    let checkpointed = checkpoint(name, key, main, wal, journal)?;
    // The caller made sure there is a free slot for this.
    pool.import_db_unchecked(name, &checkpointed)
        .map_err(CryptoKeystoreError::opfs(
            "importing the legacy database into the OPFS pool",
        ))?;

    delete_legacy_files(name).await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use rusqlite::{OpenFlags, config::DbConfig};
    use wasm_bindgen_test::wasm_bindgen_test;
    use web_sys::{FileSystemGetDirectoryOptions, FileSystemGetFileOptions};

    use super::*;
    use crate::Database;

    fn unique_name(prefix: &str) -> String {
        format!("{prefix}-{}.db", uuid::Uuid::new_v4())
    }

    /// Build CoreCrypto 11 style files: an encrypted database in WAL mode, closed without a checkpoint, so that its
    /// rows are only in the WAL. Returns the main file and the WAL.
    fn legacy_files(key: &DatabaseKey, rows: &[i64]) -> (Vec<u8>, Vec<u8>) {
        // SAFETY: as in `checkpoint`.
        let memvfs = unsafe { memvfs::install(WasmOsCallback, false) }.unwrap();
        let name = unique_name("legacy-source");
        {
            let mut conn = rusqlite::Connection::open_with_flags_and_vfs(
                &name,
                OpenFlags::SQLITE_OPEN_CREATE | OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
                "memvfs",
            )
            .unwrap();
            conn.pragma_update(None, "locking_mode", "EXCLUSIVE").unwrap();
            crate::connection::encryption::key(&mut conn, key).unwrap();
            conn.pragma_update(None, "journal_mode", "wal").unwrap();
            conn.execute_batch("PRAGMA wal_autocheckpoint = 0; CREATE TABLE legacy_probe(value INTEGER);")
                .unwrap();
            conn.set_db_config(DbConfig::SQLITE_DBCONFIG_NO_CKPT_ON_CLOSE, true)
                .unwrap();
            for row in rows {
                conn.execute("INSERT INTO legacy_probe VALUES (?1)", [row]).unwrap();
            }
        }
        let main = memvfs.export_db(&name).unwrap();
        let wal = memvfs.export_db(&format!("{name}-wal")).unwrap();
        memvfs.remove(&name).unwrap();
        memvfs.remove(&format!("{name}-wal")).unwrap();
        assert!(
            !wal.is_empty(),
            "the rows must be in the WAL for these tests to mean anything"
        );
        (main, wal)
    }

    async fn root() -> FileSystemDirectoryHandle {
        directory(&[]).await.unwrap().unwrap()
    }

    /// Write `bytes` to the legacy location of `name` plus `suffix`, creating directories as needed.
    async fn write_legacy(name: &str, suffix: &str, bytes: &[u8]) {
        let (directories, filename) = legacy_path(name);
        let mut parent = root().await;
        let options = FileSystemGetDirectoryOptions::new();
        options.set_create(true);
        for element in directories {
            parent = JsFuture::from(parent.get_directory_handle_with_options(element, &options))
                .await
                .unwrap()
                .unchecked_into();
        }
        let options = FileSystemGetFileOptions::new();
        options.set_create(true);
        let file: FileSystemFileHandle =
            JsFuture::from(parent.get_file_handle_with_options(&format!("{filename}{suffix}"), &options))
                .await
                .unwrap()
                .unchecked_into();
        let handle: FileSystemSyncAccessHandle = JsFuture::from(file.create_sync_access_handle())
            .await
            .unwrap()
            .unchecked_into();
        handle.truncate_with_u32(0).unwrap();
        let options = FileSystemReadWriteOptions::new();
        options.set_at(0.0);
        handle.write_with_u8_array_and_options(bytes, &options).unwrap();
        handle.flush().unwrap();
        handle.close();
    }

    async fn legacy_exists(name: &str, suffix: &str) -> bool {
        let (directories, filename) = legacy_path(name);
        let Some(parent) = directory(&directories).await.unwrap() else {
            return false;
        };
        read(&parent, &format!("{filename}{suffix}")).await.unwrap().is_some()
    }

    async fn legacy_probe(db: &Database) -> Vec<i64> {
        let conn = db.conn().await;
        let mut stmt = conn.prepare("SELECT value FROM legacy_probe ORDER BY value").unwrap();
        stmt.query_map([], |row| row.get(0))
            .unwrap()
            .collect::<rusqlite::Result<_>>()
            .unwrap()
    }

    async fn wipe(db: Arc<Database>) {
        Arc::into_inner(db).unwrap().wipe().await.unwrap();
    }

    #[wasm_bindgen_test]
    async fn opening_moves_a_legacy_database_into_the_pool_with_rows_only_in_its_wal() {
        let name = unique_name("legacy");
        let key = DatabaseKey::generate();
        let (main, wal) = legacy_files(&key, &[1, 2, 3]);
        write_legacy(&name, "", &main).await;
        write_legacy(&name, "-wal", &wal).await;

        let db = Database::open(&name, &key).await.unwrap();

        assert_eq!(legacy_probe(&db).await, [1, 2, 3]);
        assert!(super::super::os_unknown::pool().await.unwrap().contains(&name).unwrap());
        assert!(!legacy_exists(&name, "").await, "the legacy database must be deleted");
        assert!(!legacy_exists(&name, "-wal").await, "the legacy WAL must be deleted");
        wipe(db).await;
    }

    #[wasm_bindgen_test]
    async fn opening_moves_a_nested_legacy_database_and_removes_its_empty_directories() {
        let directory_name = format!("legacy-{}", uuid::Uuid::new_v4());
        let name = format!("{directory_name}/inner/client.db");
        let key = DatabaseKey::generate();
        let (main, wal) = legacy_files(&key, &[4]);
        write_legacy(&name, "", &main).await;
        write_legacy(&name, "-wal", &wal).await;

        let db = Database::open(&name, &key).await.unwrap();

        assert_eq!(legacy_probe(&db).await, [4]);
        assert!(
            directory(&[LEGACY_DIRECTORY, &directory_name]).await.unwrap().is_none(),
            "directories left empty by the migration must be removed"
        );
        wipe(db).await;
    }

    #[wasm_bindgen_test]
    async fn a_wrong_key_leaves_the_legacy_database_in_place() {
        let name = unique_name("legacy-wrong-key");
        let key = DatabaseKey::generate();
        let (main, wal) = legacy_files(&key, &[5]);
        write_legacy(&name, "", &main).await;
        write_legacy(&name, "-wal", &wal).await;

        assert!(Database::open(&name, &DatabaseKey::generate()).await.is_err());
        assert!(
            legacy_exists(&name, "").await,
            "the legacy database must survive a failed migration"
        );
        assert!(
            legacy_exists(&name, "-wal").await,
            "the legacy WAL must survive a failed migration"
        );
        assert!(!super::super::os_unknown::pool().await.unwrap().contains(&name).unwrap());

        let db = Database::open(&name, &key).await.unwrap();
        assert_eq!(legacy_probe(&db).await, [5]);
        wipe(db).await;
    }

    /// The worker may die after the import committed but before the legacy files were deleted. The database in the
    /// pool then already has the data, and may have changed since, so the legacy files must not be imported again.
    #[wasm_bindgen_test]
    async fn legacy_files_left_after_an_import_are_deleted_not_imported() {
        let name = unique_name("legacy-leftover");
        let key = DatabaseKey::generate();
        let (main, wal) = legacy_files(&key, &[6]);
        write_legacy(&name, "", &main).await;
        write_legacy(&name, "-wal", &wal).await;
        let db = Database::open(&name, &key).await.unwrap();
        db.conn()
            .await
            .execute("INSERT INTO legacy_probe VALUES (7)", [])
            .unwrap();
        Arc::into_inner(db).unwrap().close().await.unwrap();

        // As if deleting them had failed.
        write_legacy(&name, "", &main).await;
        write_legacy(&name, "-wal", &wal).await;

        let db = Database::open(&name, &key).await.unwrap();
        assert_eq!(legacy_probe(&db).await, [6, 7]);
        assert!(!legacy_exists(&name, "").await, "leftover legacy files must be deleted");
        assert!(
            !legacy_exists(&name, "-wal").await,
            "leftover legacy files must be deleted"
        );
        wipe(db).await;
    }
}
