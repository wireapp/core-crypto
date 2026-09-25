//! This module is compiled only when `target_os = "unknown"`.
//!
//! This gives us a place to put OPFS-specific items.

use std::{cell::RefCell, rc::Rc, time::Duration};

use async_trait::async_trait;
use sqlite_wasm_rs::WasmOsCallback;
use sqlite_wasm_vfs::opfs_jspi::{self, OpfsJspi};

use super::{ManagedConnection, SqliteGuard};
use crate::{CryptoKeystoreError, CryptoKeystoreResult, DatabaseKey};

// To use sqlite3-multiple-ciphers, you have to prepend the VFS name with `multipleciphers-`.
// This is true even if you use a non-default VFS name.
const VFS_NAME: &str = "core-crypto";
const VFS_NAME_WITH_ENCRYPTION: &str = "multipleciphers-core-crypto";

thread_local! {
    static VFS: RefCell<Option<Rc<OpfsJspi>>> = const { RefCell::new(None) };
}

// rusqlite 0.38 uses sqlite-wasm-rs 0.5, whose host implements rsqlite-vfs 0.1.
// Adapt those same host callbacks to the new VFS API without linking two SQLite libraries.
#[derive(Default)]
struct OpfsOs;

impl rsqlite_vfs::OsCallback for OpfsOs {
    fn sleep(&self, duration: Duration) {
        <WasmOsCallback as sqlite_wasm_rs::utils::OsCallback>::sleep(duration);
    }

    fn random(&self, buf: &mut [u8]) -> usize {
        <WasmOsCallback as sqlite_wasm_rs::utils::OsCallback>::random(buf);
        buf.len()
    }

    fn epoch_timestamp_in_ms(&self) -> rsqlite_vfs::VfsResult<i64> {
        Ok(<WasmOsCallback as sqlite_wasm_rs::utils::OsCallback>::epoch_timestamp_in_ms())
    }
}

/// Install once for this Wasm instance.
fn get_vfs_util() -> CryptoKeystoreResult<Rc<OpfsJspi>> {
    if let Some(vfs) = VFS.with_borrow(Clone::clone) {
        return Ok(vfs);
    }
    let vfs = Rc::new(opfs_jspi::install::<OpfsOs>(VFS_NAME, VFS_NAME, false)?);
    VFS.with_borrow_mut(|slot| *slot = Some(vfs.clone()));
    Ok(vfs)
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

    let _sqlite = SqliteGuard::lock();
    let vfs_util = FsAbstraction(get_vfs_util()?);
    let already_exists = vfs_util
        .contains(name)
        .map_err(CryptoKeystoreError::opfs("checking database existence"))?;
    // the flags we use here are equivalent to the defaults, except we don't engage uri handling
    // https://docs.rs/rusqlite/latest/rusqlite/struct.Connection.html#method.open
    let mut conn = ManagedConnection::from(rusqlite::Connection::open_with_flags_and_vfs(
        name,
        rusqlite::OpenFlags::SQLITE_OPEN_CREATE
            | rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE
            | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
        VFS_NAME_WITH_ENCRYPTION,
    )?);

    // Set before encryption, schema reads, or reopening a database already in WAL mode.
    // The VFS owns the directory exclusively and rejects a second connection to this file.
    conn.pragma_update(None, "locking_mode", "EXCLUSIVE")?;

    if already_exists {
        super::encryption::decrypt(&mut conn, key)?;
    } else {
        super::encryption::rekey(&mut conn, key)?;
    }

    // Not gated on `already_exists`: the file also exists after an import which failed or was interrupted,
    // and the import must run again in that case. `maybe_migrate` decides from the database's own state.
    super::idb_migration::maybe_migrate(name, key, &mut conn).await?;

    Ok((conn, vfs_util))
}

#[derive(derive_more::Debug, derive_more::Deref, derive_more::DerefMut)]
#[debug("OpfsJspi")]
pub(super) struct FsAbstraction(Rc<OpfsJspi>);

// SAFETY: so this is a lie, it's not safe.
// But on the other hand we only ever compile this where `target_os = "unknown"`,
// specifically `wasm32-unknown-unknown`, where there is never more than one thread anyway.
// So we can be confident about getting away with it.
unsafe impl Send for FsAbstraction {}

#[async_trait(?Send)]
impl super::Filesystem for FsAbstraction {
    async fn delete(&self, path: &str) -> CryptoKeystoreResult<()> {
        let _sqlite = SqliteGuard::lock();
        // SQLite normally removes these on close, but persistent journals may remain.
        for name in [path.to_owned(), format!("{path}-journal"), format!("{path}-wal")] {
            if self
                .contains(&name)
                .map_err(CryptoKeystoreError::opfs("checking file before deletion"))?
            {
                self.remove(&name).map_err(CryptoKeystoreError::opfs("deleting file"))?;
            }
        }
        Ok(())
    }
}
