//! A minimal SQLite VFS storing files in OPFS.
//!
//! OPFS synchronous access handles are only available in dedicated workers, so a small worker
//! (see `opfs_vfs.js`) owns them. SQLite stays on the calling thread: each VFS callback makes one
//! request to the worker and suspends through JSPI until the reply arrives.
//!
//! Consequently, all SQLite entry must happen from within a JSPI export, and must hold
//! `SqliteGuard` so that no other JSPI export enters SQLite while a callback is suspended.
//!
//! Locks are no-ops: we use `locking_mode=EXCLUSIVE` and one connection per database. Another tab
//! (or a second connection) cannot open a file whose access handle is held, and gets `SQLITE_BUSY`.

#![allow(deprecated)] // wasm-bindgen's JSPI API is experimental.

use std::{cell::RefCell, collections::VecDeque};

use async_lock::{Mutex, MutexGuard};
use js_sys::{
    Promise, Reflect, Uint8Array,
    futures::{future_to_promise, jspi_block_on_promise},
};
use rsqlite_vfs::{
    AccessMode, DeviceCharacteristics, MemChunksFile, OpenOptions, OpenRequest, OpenedFile, OsCallback,
    SQLiteIoMethods, SQLiteVfs, SyncOptions, VfsError, VfsErrorCode, VfsFile, VfsResult, VfsStore,
};
use wasm_bindgen::{JsValue, prelude::wasm_bindgen};

#[wasm_bindgen(module = "/src/connection/opfs_vfs.js")]
extern "C" {
    fn start(directory: &str) -> Promise;
    fn exists(name: &str) -> Promise;
    fn open(name: &str, create: bool) -> Promise;
    fn remove(name: &str) -> Promise;
    fn read(id: f64, offset: f64, length: f64) -> Promise;
    fn write(id: f64, offset: f64, bytes: Uint8Array) -> Promise;
    fn truncate(id: f64, length: f64) -> Promise;
    fn size(id: f64) -> Promise;
    fn flush(id: f64) -> Promise;
    fn close(id: f64) -> Promise;
    #[wasm_bindgen(js_name = scheduleCleanup)]
    fn schedule_cleanup(exports: &JsValue);
}

static SQLITE: Mutex<()> = Mutex::new(());

thread_local! {
    static CLEANUP: RefCell<VecDeque<Box<dyn FnOnce()>>> = RefCell::default();
}

/// Exclusive entry to SQLite for this Wasm instance.
///
/// Hold this around one complete SQLite operation.
/// It is non-reentrant. Contended acquisition suspends, so it must happen within a JSPI export.
pub(crate) struct SqliteGuard {
    _guard: MutexGuard<'static, ()>,
}

impl SqliteGuard {
    pub(crate) fn lock() -> Self {
        let guard = SQLITE.try_lock().unwrap_or_else(|| {
            let slot = std::rc::Rc::new(RefCell::new(None));
            let result = slot.clone();
            jspi_block_on_promise(&future_to_promise(async move {
                *result.borrow_mut() = Some(SQLITE.lock().await);
                Ok(JsValue::UNDEFINED)
            }))
            .expect("SQLite entry requires a JSPI boundary");
            slot.take().expect("SQLite lock acquired")
        });
        // Pop before invoking: cleanup may suspend or enqueue more cleanup.
        while let Some(cleanup) = CLEANUP.with_borrow_mut(VecDeque::pop_front) {
            cleanup();
        }
        Self { _guard: guard }
    }
}

/// Defers SQLite cleanup from `Drop`, which may run outside of a JSPI export.
///
/// The cleanup runs under `SqliteGuard`, within the next JSPI entry. It must not acquire the guard itself.
pub fn defer(cleanup: impl FnOnce() + 'static) {
    CLEANUP.with_borrow_mut(|queue| queue.push_back(Box::new(cleanup)));
    schedule_cleanup(&wasm_bindgen::exports());
}

#[wasm_bindgen(jspi)]
#[expect(
    unreachable_pub,
    reason = "called through the Wasm exports object by `scheduleCleanup`"
)]
pub fn core_crypto_keystore_sqlite_cleanup() {
    let _sqlite = SqliteGuard::lock();
}

/// Blocks on a worker request through JSPI, converting failures to [`VfsError`].
fn settle(promise: Promise, code: VfsErrorCode) -> VfsResult<JsValue> {
    jspi_block_on_promise(&promise).map_err(|value| {
        let get = |key: &str| Reflect::get(&value, &key.into()).ok().and_then(|x| x.as_string());
        let name = get("name");
        let code = match name.as_deref() {
            Some("QuotaExceededError") => VfsErrorCode::Full,
            Some("NoModificationAllowedError") if code == VfsErrorCode::CantOpen => VfsErrorCode::Busy,
            Some("NotFoundError") if code == VfsErrorCode::IoDelete => VfsErrorCode::IoDeleteNoEntry,
            _ => code,
        };
        let message = get("message").unwrap_or_else(|| format!("{value:?}"));
        VfsError::new(
            code,
            format!("OPFS {}: {message}", name.as_deref().unwrap_or("error")).into(),
        )
    })
}

/// Maps a flat SQLite filename injectively to a portable OPFS name.
fn physical_name(name: &str) -> String {
    format!("f-{}", hex::encode(name))
}

pub(super) enum WorkerFile {
    /// A file held open by the worker, by its id.
    Opfs(f64),
    /// An anonymous temporary file.
    Memory(MemChunksFile),
}

impl VfsFile for WorkerFile {
    fn device_characteristics(&self) -> DeviceCharacteristics {
        DeviceCharacteristics::UNDELETABLE_WHEN_OPEN
    }

    fn read(&mut self, buf: &mut [u8], offset: u64) -> VfsResult<usize> {
        let id = match self {
            Self::Opfs(id) => *id,
            Self::Memory(memory) => return memory.read(buf, offset),
        };
        let bytes = Uint8Array::new(&settle(
            read(id, offset as f64, buf.len() as f64),
            VfsErrorCode::IoRead,
        )?);
        // The worker reads at most `buf.len()` bytes.
        let count = bytes.length() as usize;
        bytes.copy_to(&mut buf[..count]);
        Ok(count)
    }

    fn write(&mut self, buf: &[u8], offset: u64) -> VfsResult<()> {
        match self {
            Self::Opfs(id) => settle(write(*id, offset as f64, Uint8Array::from(buf)), VfsErrorCode::IoWrite).map(drop),
            Self::Memory(memory) => memory.write(buf, offset),
        }
    }

    fn truncate(&mut self, size: u64) -> VfsResult<()> {
        match self {
            Self::Opfs(id) => settle(truncate(*id, size as f64), VfsErrorCode::IoTruncate).map(drop),
            Self::Memory(memory) => memory.truncate(size),
        }
    }

    fn sync(&mut self, _options: SyncOptions) -> VfsResult<()> {
        match self {
            Self::Opfs(id) => settle(flush(*id), VfsErrorCode::IoSync).map(drop),
            Self::Memory(_) => Ok(()),
        }
    }

    fn size(&self) -> VfsResult<u64> {
        let id = match self {
            Self::Opfs(id) => *id,
            Self::Memory(memory) => return memory.size(),
        };
        let size = settle(size(id), VfsErrorCode::IoStat)?;
        size.as_f64()
            .map(|size| size as u64)
            .ok_or_else(|| VfsError::new(VfsErrorCode::IoStat, "invalid OPFS file size".into()))
    }

    // No-op: the worker holds a sync access handle for every open file, and those are exclusive.
    fn lock(&mut self, _level: rsqlite_vfs::LockLevel) -> VfsResult<()> {
        Ok(())
    }

    // No-op for the same reason as `lock`.
    fn unlock(&mut self, _level: rsqlite_vfs::LockLevel) -> VfsResult<()> {
        Ok(())
    }

    // No other connection can have the file open, so none can hold a reserved lock.
    fn check_reserved_lock(&self) -> VfsResult<bool> {
        Ok(false)
    }
}

pub(super) struct Store;

impl VfsStore for Store {
    type File = WorkerFile;
    type AppData = Box<dyn OsCallback>;

    fn open_file(_: &Self::AppData, request: OpenRequest<'_>) -> VfsResult<OpenedFile<WorkerFile>> {
        let options = request.options;
        let file = match request.filename {
            Some(filename) => {
                let id = settle(
                    open(&physical_name(filename.path()), options.create()),
                    VfsErrorCode::CantOpen,
                )?;
                WorkerFile::Opfs(id.as_f64().expect("worker returns a numeric file id"))
            }
            None => WorkerFile::Memory(MemChunksFile::default()),
        };
        Ok(OpenedFile {
            file,
            access: options.access(),
        })
    }

    fn close_file(data: &Self::AppData, name: Option<&str>, file: WorkerFile, options: OpenOptions) -> VfsResult<()> {
        if let WorkerFile::Opfs(id) = file {
            settle(close(id), VfsErrorCode::IoClose)?;
        }
        match name {
            Some(name) if options.delete_on_close() => Self::delete_file(data, name, false),
            _ => Ok(()),
        }
    }

    fn access(_: &Self::AppData, name: &str, _mode: AccessMode) -> VfsResult<bool> {
        contains(name)
    }

    fn full_pathname(_: &Self::AppData, name: &str) -> VfsResult<String> {
        Ok(name.to_owned())
    }

    fn delete_file(_: &Self::AppData, name: &str, _sync_dir: bool) -> VfsResult<()> {
        delete(name)
    }
}

pub(super) struct Io;

impl SQLiteIoMethods for Io {
    type Store = Store;
}

pub(super) struct Vfs;

impl SQLiteVfs<Io> for Vfs {
    type Os = dyn OsCallback;

    fn os(data: &Box<dyn OsCallback>) -> &Self::Os {
        &**data
    }
}

/// Starts the worker on the OPFS directory `name` and registers the VFS as `name`. Idempotent.
///
/// The caller must hold `SqliteGuard`.
pub(super) fn install(name: &str, os: impl OsCallback + 'static, _guard: &SqliteGuard) -> VfsResult<()> {
    let registration_error =
        |error: rsqlite_vfs::RegisterVfsError| VfsError::new(VfsErrorCode::CantOpen, error.to_string().into());
    // SAFETY: the registry lookup is serialized by the caller holding `SqliteGuard`.
    if unsafe { rsqlite_vfs::registered_vfs(name) }
        .map_err(registration_error)?
        .is_some()
    {
        return Ok(());
    }
    settle(start(name), VfsErrorCode::CantOpen)?;
    // SAFETY: registration is serialized by the caller holding `SqliteGuard`,
    // and `Io`/`Vfs` use the matching store and callback types.
    let registration =
        unsafe { rsqlite_vfs::register_vfs::<Io, Vfs>(name, Box::new(os), false) }.map_err(registration_error)?;
    // The VFS lives as long as the Wasm instance.
    registration.into_raw();
    Ok(())
}

pub(super) fn contains(name: &str) -> VfsResult<bool> {
    Ok(settle(exists(&physical_name(name)), VfsErrorCode::IoAccess)?.is_truthy())
}

pub(super) fn delete(name: &str) -> VfsResult<()> {
    settle(remove(&physical_name(name)), VfsErrorCode::IoDelete).map(drop)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Runs rsqlite-vfs's file conformance checks against a real worker-backed file.
    #[core_crypto_macros::jspi_wasm_bindgen_test]
    async fn worker_file_passes_the_vfs_file_test_suite() {
        let sqlite = SqliteGuard::lock();
        super::super::os_unknown::ensure_vfs_installed(&sqlite).unwrap();
        let name = physical_name(&format!("vfs-suite-{}", uuid::Uuid::new_v4()));
        let id = settle(open(&name, true), VfsErrorCode::CantOpen)
            .unwrap()
            .as_f64()
            .unwrap();
        let mut file = WorkerFile::Opfs(id);
        rsqlite_vfs::test_suite::test_vfs_file(&mut file).unwrap();
        settle(close(id), VfsErrorCode::IoClose).unwrap();
        settle(remove(&name), VfsErrorCode::IoDelete).unwrap();
    }
}
