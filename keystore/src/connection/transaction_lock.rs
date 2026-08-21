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

#[cfg(all(test, feature = "cross-process-lock", not(target_os = "unknown")))]
mod tests {
    use std::time::Duration;

    use futures_lite::future;
    use smol::Timer;

    use crate::{CryptoKeystoreError, Database, DatabaseKey};

    /// Long enough that a lock which is genuinely free gets taken well within it.
    const TIMEOUT: Duration = Duration::from_secs(10);
    /// Short enough to keep the suite quick, since the expected outcome is that nothing happens.
    const CONTENTION_WINDOW: Duration = Duration::from_millis(250);

    /// Two `Database` handles over one path are what a second process looks like to the file lock:
    /// each has its own semaphore and its own open lock file, so only the file lock can separate
    /// them. That makes this a faithful stand-in for genuine cross-process contention without
    /// having to spawn one.
    async fn two_handles(dir: &std::path::Path) -> (std::sync::Arc<Database>, std::sync::Arc<Database>) {
        let path = dir.join("keystore.db");
        let path = path.to_str().expect("temp dir path is utf-8");
        let key = DatabaseKey::generate();
        (
            Database::open(path, &key).await.expect("opening the first handle"),
            Database::open(path, &key).await.expect("opening the second handle"),
        )
    }

    #[test]
    fn an_immediate_transaction_is_refused_while_another_handle_holds_one() {
        future::block_on(async {
            let dir = tempfile::tempdir().unwrap();
            let (first, second) = two_handles(dir.path()).await;

            let transaction = first.new_transaction().await.unwrap();

            match second.try_new_immediate_transaction().await {
                Err(CryptoKeystoreError::TransactionInProgress) => {}
                Err(error) => panic!("expected the second handle to be locked out, got {error}"),
                Ok(_) => panic!("the second handle started a transaction while the first held one"),
            }

            // committing releases the lock, so the other handle can take it
            transaction.commit().await.unwrap();
            second.try_new_immediate_transaction().await.unwrap();
        });
    }

    #[test]
    fn a_waiting_transaction_blocks_until_the_other_handle_is_done() {
        future::block_on(async {
            let dir = tempfile::tempdir().unwrap();
            let (first, second) = two_handles(dir.path()).await;

            let transaction = first.new_transaction().await.unwrap();

            // the file lock is held elsewhere, so this must not resolve
            let acquired = future::or(async { Some(second.new_transaction().await) }, async {
                Timer::after(CONTENTION_WINDOW).await;
                None
            })
            .await;
            assert!(
                acquired.is_none(),
                "the second handle acquired a lock it should have waited for"
            );

            // rolling back by drop releases the lock just as committing does
            drop(transaction);

            future::or(async { Some(second.new_transaction().await) }, async {
                Timer::after(TIMEOUT).await;
                None
            })
            .await
            .expect("timed out waiting for the released lock")
            .unwrap();
        });
    }

    /// Dropping a pending acquisition must not strand the lock: the blocking acquire may still
    /// land after the future is gone, and its guard has to release what it took.
    #[test]
    fn abandoning_a_pending_acquisition_leaves_the_lock_free() {
        future::block_on(async {
            let dir = tempfile::tempdir().unwrap();
            let (first, second) = two_handles(dir.path()).await;

            let transaction = first.new_transaction().await.unwrap();
            // start waiting, then walk away
            future::or(async { Some(second.new_transaction().await) }, async {
                Timer::after(CONTENTION_WINDOW).await;
                None
            })
            .await;
            drop(transaction);

            // the abandoned wait may win the race for the lock, but only transiently; retry until
            // its guard has been dropped
            let acquired = future::or(
                async {
                    loop {
                        if let Ok(transaction) = second.try_new_immediate_transaction().await {
                            return Some(transaction);
                        }
                        Timer::after(Duration::from_millis(10)).await;
                    }
                },
                async {
                    Timer::after(TIMEOUT).await;
                    None
                },
            )
            .await;
            assert!(acquired.is_some(), "the abandoned acquisition stranded the file lock");
        });
    }

    #[test]
    fn wiping_a_database_removes_its_lock_file() {
        future::block_on(async {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("keystore.db");
            let database = Database::open(path.to_str().unwrap(), &DatabaseKey::generate())
                .await
                .unwrap();

            database.new_transaction().await.unwrap().commit().await.unwrap();

            let lock_file = dir.path().join("keystore.db-cc-tx.lock");
            assert!(lock_file.exists(), "expected a lock file next to the database");

            std::sync::Arc::into_inner(database).unwrap().wipe().await.unwrap();
            assert!(!lock_file.exists(), "wipe left the lock file behind");
        });
    }
}
