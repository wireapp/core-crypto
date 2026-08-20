use std::{
    fs::{File, TryLockError},
    io,
    sync::Arc,
};

use crate::{CryptoKeystoreError, CryptoKeystoreResult};

/// Appended to the database path to name its lock file.
///
/// The lock deliberately lives on a sibling file rather than on the database itself: SQLite
/// takes its own advisory locks on the database, and on Windows those are byte-range locks in
/// the very range `File::lock` claims, so locking the database directly would collide with it.
const LOCK_FILE_SUFFIX: &str = "-cc-tx.lock";

fn lock_file_path(database_path: &str) -> String {
    format!("{database_path}{LOCK_FILE_SUFFIX}")
}

/// Remove the lock file belonging to the database at `database_path`.
///
/// Only meaningful when the database itself is going away; a lock file with no database is
/// just litter. Safe to call while still holding the lock, as the lock lives on the open file
/// rather than on its name.
pub(crate) async fn remove_lock_file(database_path: &str) -> CryptoKeystoreResult<()> {
    let path = lock_file_path(database_path);
    match async_fs::remove_file(&path).await {
        // the lock file is only created on demand, so its absence is the normal case for a
        // database which never opened a transaction
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(()),
        result => result.map_err(|source| CryptoKeystoreError::TransactionLock { path, source }),
    }
}

/// An advisory lock on a file next to the database, held for as long as a transaction runs.
///
/// The lock is released by the OS if the holding process dies, so a crashed peer cannot wedge
/// everyone else out of the database.
#[derive(Debug)]
pub(crate) struct FileLock {
    file: File,
    path: String,
}

impl FileLock {
    /// Open (creating if necessary) the lock file guarding the database at `database_path`.
    ///
    /// Produces `None` for in-memory databases, which have an empty path and are unreachable
    /// from other processes anyway.
    pub(crate) fn open(database_path: &str) -> CryptoKeystoreResult<Option<Arc<Self>>> {
        if database_path.is_empty() {
            return Ok(None);
        }

        let path = lock_file_path(database_path);
        let file = File::create(&path).map_err(|source| CryptoKeystoreError::TransactionLock {
            path: path.clone(),
            source,
        })?;

        Ok(Some(Arc::new(Self { file, path })))
    }

    fn error(&self, source: io::Error) -> CryptoKeystoreError {
        CryptoKeystoreError::TransactionLock {
            path: self.path.clone(),
            source,
        }
    }

    /// Wait until no other process holds this lock, then take it.
    pub(crate) async fn lock(self: &Arc<Self>) -> CryptoKeystoreResult<FileLockGuard> {
        let lock = self.clone();
        // `File::lock` parks the calling thread, so it goes to the blocking pool; that keeps
        // us independent of whichever async runtime the consumer is driving us with.
        //
        // The guard is constructed inside the closure rather than out here so that this stays
        // cancellation-safe: dropping the returned future lets the blocking call finish and
        // then drops its output, which releases the lock we just took. Returning the bare
        // `Arc` instead would silently leave the lock held until the database is closed.
        blocking::unblock(move || match lock.file.lock() {
            Ok(()) => Ok(FileLockGuard { lock }),
            Err(source) => Err(lock.error(source)),
        })
        .await
    }

    /// Take this lock, or produce `None` if another process holds it.
    pub(crate) fn try_lock(self: &Arc<Self>) -> CryptoKeystoreResult<Option<FileLockGuard>> {
        match self.file.try_lock() {
            Ok(()) => Ok(Some(FileLockGuard { lock: self.clone() })),
            Err(TryLockError::WouldBlock) => Ok(None),
            Err(TryLockError::Error(source)) => Err(self.error(source)),
        }
    }
}

/// Releases the file lock when dropped.
pub(crate) struct FileLockGuard {
    lock: Arc<FileLock>,
}

impl Drop for FileLockGuard {
    fn drop(&mut self) {
        // unlocking is a single non-blocking syscall, so it is fine to run inline here
        if let Err(error) = self.lock.file.unlock() {
            // dropping the file would release the lock too, but the `FileLock` outlives this
            // guard, so a failure here really does leave the lock held; all we can do is say so
            panic!(
                "failed to release the cross-process transaction lock at {}: {error}",
                self.lock.path
            );
        }
    }
}
