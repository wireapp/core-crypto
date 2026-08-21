//! Exclusion between keystore transactions.
//!
//! At most one keystore transaction may be in flight against a given database at a time.
//! The in-process half of that guarantee is a [`Semaphore`]; the cross-process half, compiled in
//! by the `cross-process-lock` feature, is an advisory lock on a file next to the database.
//!
//! The two halves are always taken together, and in that order: the semaphore first, so tasks
//! within this process queue up in the async runtime instead of piling blocking-pool threads onto
//! a file lock; the file lock second, so at most one process at a time is past both.
//!
//! [`Database`]: crate::Database

#[cfg(all(feature = "cross-process-lock", target_os = "unknown"))]
compile_error!(
    "the `cross-process-lock` feature locks a file in the local filesystem, which the wasm \
     keystore (backed by IndexedDB) has none of; disable it for `target_os = \"unknown\"`"
);

use std::sync::Arc;

use async_lock::{Semaphore, SemaphoreGuardArc};

use crate::CryptoKeystoreResult;
#[cfg(feature = "cross-process-lock")]
use crate::connection::file_lock::{FileLock, FileLockGuard};

/// Only one keystore transaction may be in flight against a database at a time.
const ALLOWED_CONCURRENT_TRANSACTIONS_COUNT: usize = 1;

/// Gates the start of a keystore transaction.
#[derive(Debug)]
pub(crate) struct TransactionLock {
    // we need this `Arc` so we can create an owned guard, so that the transaction doesn't need
    // a self-referential lifetime into the database.
    semaphore: Arc<Semaphore>,
    #[cfg(feature = "cross-process-lock")]
    /// `None` for in-memory databases, and whenever cross-process locking is compiled out.
    file: Option<Arc<FileLock>>,
}

/// Proof that its holder is the only one running a keystore transaction against this database.
///
/// Both halves of the lock are released when this is dropped.
pub(crate) struct TransactionGuard {
    _semaphore: SemaphoreGuardArc,
    #[cfg(feature = "cross-process-lock")]
    _file: Option<FileLockGuard>,
}

impl TransactionLock {
    /// Construct the lock guarding the database at `database_path`.
    ///
    /// `database_path` is empty for in-memory databases, which no other process can reach, so
    /// those get the in-process half only.
    pub(crate) fn new(#[allow(unused)] database_path: &str) -> CryptoKeystoreResult<Self> {
        Ok(Self {
            semaphore: Arc::new(Semaphore::new(ALLOWED_CONCURRENT_TRANSACTIONS_COUNT)),
            #[cfg(feature = "cross-process-lock")]
            file: FileLock::open(database_path)?,
        })
    }

    /// Wait until no other transaction is in flight, in this process or in any other.
    pub(crate) async fn acquire(&self) -> CryptoKeystoreResult<TransactionGuard> {
        let semaphore = self.semaphore.acquire_arc().await;
        #[cfg(feature = "cross-process-lock")]
        let file = match self.file.as_ref() {
            Some(file) => Some(file.lock().await?),
            None => None,
        };
        Ok(TransactionGuard {
            _semaphore: semaphore,
            #[cfg(feature = "cross-process-lock")]
            _file: file,
        })
    }

    /// Acquire the lock, or produce `None` if a transaction is already in flight.
    pub(crate) fn try_acquire(&self) -> CryptoKeystoreResult<Option<TransactionGuard>> {
        let Some(semaphore) = self.semaphore.try_acquire_arc() else {
            return Ok(None);
        };
        #[cfg(feature = "cross-process-lock")]
        let file = match self.file.as_ref() {
            Some(file) => match file.try_lock()? {
                Some(guard) => Some(guard),
                // Another process holds the lock. Returning here drops `semaphore`, releasing the
                // in-process half again: it would be wrong to make local callers queue behind a
                // transaction we never started.
                None => return Ok(None),
            },
            None => None,
        };
        Ok(Some(TransactionGuard {
            _semaphore: semaphore,
            #[cfg(feature = "cross-process-lock")]
            _file: file,
        }))
    }
}
