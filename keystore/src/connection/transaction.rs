//! The methods in this module handle keystore transactions.
//!
//! Keystore transactions are "fake", in-memory persistence of database operations over time.
//! They're required because actual [`rusqlite::Transaction`] is `!Send + !Sync`, and we need
//! `Send` at a minimum in order to keep the transaction around and manipulate it concurrently
//! from various tasks.

use std::sync::Arc;

use crate::{
    CryptoKeystoreError, CryptoKeystoreResult, Database, UniqueArc, transaction::Transaction,
    unique_arc::ArcWithReadGuard,
};

/// These impls control the keystore transaction lifecycle.
impl Database {
    /// Waits for the current transaction to be committed or rolled back, then starts a new one.
    pub async fn new_transaction(self: &Arc<Self>) -> CryptoKeystoreResult<UniqueArc<Transaction>> {
        let semaphore = self.transaction_semaphore.acquire_arc().await;
        Transaction::new(semaphore, self.clone()).await
    }

    /// Start a new transaction if no other transaction is currently in progress.
    ///
    /// If a transaction is currently in progress, this will produce a `TransactionInProgress` error.
    pub async fn try_new_immediate_transaction(self: &Arc<Self>) -> CryptoKeystoreResult<UniqueArc<Transaction>> {
        let semaphore = self
            .transaction_semaphore
            .try_acquire_arc()
            .ok_or(CryptoKeystoreError::TransactionInProgress)?;
        Transaction::new(semaphore, self.clone()).await
    }

    /// Do an operation on a new keystore transaction on this database.
    ///
    /// This is a convenience method abstracting over the transaction lifecycle;
    /// it creates a new transaction (including waiting for any existing transaction to finish),
    /// then performs its operation.
    ///
    /// If the operation succeeds, the transaction is committed.
    /// Otherwise, it is rolled back.
    pub async fn transactionally<R>(
        self: &Arc<Self>,
        operation: impl AsyncFnOnce(&Transaction) -> CryptoKeystoreResult<R>,
    ) -> CryptoKeystoreResult<R> {
        let semaphore = self.transaction_semaphore.acquire_arc().await;
        let transaction = Transaction::new(semaphore, self.clone()).await?;

        let result = operation(&transaction).await;
        if result.is_ok() {
            transaction.commit().await?;
        }
        // otherwise implicit rollback on tx drop

        result
    }

    /// Do an operation on an existing keystore transaction.
    ///
    /// This does not create, commit, or abort an existing transaction; it just provides a standardized
    /// helper to acquire it while creating appropriate errors.
    pub(crate) async fn with_transaction<R>(
        &self,
        operation: impl AsyncFnOnce(&Transaction) -> CryptoKeystoreResult<R>,
    ) -> CryptoKeystoreResult<R> {
        let guard = self.transaction.lock().await;
        let transaction = guard
            .as_ref()
            .ok_or(CryptoKeystoreError::MutatingOperationWithoutTransaction)?
            .upgrade()
            .await
            .ok_or(CryptoKeystoreError::MutatingOperationWithoutTransaction)?;

        operation(&transaction).await
    }

    /// Ensure a transaction exists, passing it to the operation.
    ///
    /// Ideally this method wouldn't exist; in most cases, [`Self::transactionally`]
    /// or [`Self::with_transaction`] are the simpler picks. Every usage of this is a step
    /// away from the long-term goal of separating transactions from the database entirely.
    /// At present, this is designed for the FFI version of `PkiEnvironment`, which cannot
    /// natively know whether a CC transaction is currently in-progress or not.
    ///
    /// If a transaction is already in progress, perform the operation and pass on its result
    /// without affecting the transaction lifecycle at all, whether or not the operation succeeded.
    ///
    /// NOTE: if the transaction was already in progress, its owner's `.commit()` will block until
    /// the operation here has completed.
    ///
    /// If a transaction was _not_ already in progress, create one and then perform the operation.
    /// If the operation succeeded, commit the transaction; otherwise, let it rollback by drop.
    /// Then return the result.
    ///
    /// If the operation succeeded but the commit failed, the commit error masks the operation's
    /// success.
    ///
    /// Because the operation and therefore this overall function can return an arbitrary error type,
    /// and there is not necessarily a direct relation between [`CryptoKeystoreError`] and `E`,
    /// this function requires an explicit mapping function to be provided.
    ///
    /// NOTE: Because of TOCTOU, there is an interval between when we check if an existing
    /// transaction exists, and when we create our own. If a separate process creates a transaction
    /// during that interval, then this function must wait for that external transaction to
    /// complete before it can acquire the semaphore. This might be surprising, but isn't
    /// worth putting in the effort to change; it's not strictly a bug.
    pub async fn ensure_transaction<T, E>(
        self: &Arc<Self>,
        operation: impl AsyncFnOnce(&Transaction) -> Result<T, E>,
        map_err: impl Fn(CryptoKeystoreError) -> E,
    ) -> Result<T, E> {
        #[derive(derive_more::Deref, derive_more::From)]
        enum TxHandle {
            /// Someone else created this transaction and we have a guard over it
            Borrowed(#[deref(forward)] ArcWithReadGuard<Transaction>),
            /// We created this transaction and need to commit it ourselves
            Owned(#[deref(forward)] UniqueArc<Transaction>),
        }

        // don't keep the lock alive, to prevent deadlocks
        let weak = (*self.transaction.lock().await).clone();
        // still waiting on `Option::async_map`, `Option::async_and_then`
        let existing = match weak {
            Some(weak) => weak.upgrade_without_type_erasure().await,
            None => None,
        };
        let handle: TxHandle = match existing {
            Some(existing) => existing.into(),
            None => self.new_transaction().await.map_err(&map_err)?.into(),
        };

        let result = operation(&handle).await;

        if let TxHandle::Owned(tx) = handle
            && result.is_ok()
        {
            tx.commit().await.map_err(&map_err)?;
        }

        result
    }

    /// Merge database records with the active transaction's view of them.
    ///
    /// If no transaction is in progress, the database records are returned unchanged.
    pub(super) async fn merge_with_transaction<E>(
        &self,
        persisted_records: Vec<E>,
        merge: impl AsyncFnOnce(&Transaction, Vec<E>) -> CryptoKeystoreResult<Vec<E>>,
    ) -> CryptoKeystoreResult<Vec<E>> {
        let guard = self.transaction.lock().await;
        let Some(weak) = guard.as_ref() else {
            return Ok(persisted_records);
        };
        let Some(tx) = weak.upgrade().await else {
            return Ok(persisted_records);
        };
        merge(&tx, persisted_records).await
    }
}

#[cfg(all(test, not(target_os = "unknown")))]
mod tests {
    use std::{future::Future, time::Duration};

    use futures_lite::future;
    use smol::Timer;

    use crate::{CryptoKeystoreError, Database, entities::ConsumerData, traits::FetchFromDatabase as _};

    const OUTER: &[u8] = b"written by the outer operation";
    const NESTED: &[u8] = b"written by the nested operation";

    /// How long [`without_deadlock`] waits before declaring a hang.
    ///
    /// Generous, because overshooting only costs time on an already-failing test, while
    /// undershooting would make the suite flaky on a loaded CI machine.
    const TIMEOUT: Duration = Duration::from_secs(10);

    /// Distinguishes an operation failure from a keystore failure, so that the rollback test can
    /// assert that the error coming back out is the one the operation produced.
    #[derive(Debug, derive_more::From)]
    enum TestError {
        Keystore(CryptoKeystoreError),
        Operation,
    }

    fn consumer_data(content: &[u8]) -> ConsumerData {
        ConsumerData {
            content: content.to_owned(),
        }
    }

    /// Run `fut` to completion, panicking rather than hanging if it takes too long.
    ///
    /// Every interesting failure mode in these tests is a deadlock, which would otherwise stall
    /// the whole test run instead of reporting which case broke.
    async fn without_deadlock<T>(fut: impl Future<Output = T>) -> T {
        future::or(async { Some(fut.await) }, async {
            Timer::after(TIMEOUT).await;
            None
        })
        .await
        .expect("timed out; `ensure_transaction` deadlocked")
    }

    /// Meta-test: [`without_deadlock`] can actually observe a hang.
    ///
    /// The other tests in this module lean on that guard to turn a deadlock regression into a
    /// named failure instead of a stalled test run. If the guard ever stopped firing — say because
    /// [`Timer`] no longer gets driven under [`future::block_on`] — those tests would keep passing
    /// while silently losing the property they exist to check, so it's worth pinning down.
    ///
    /// Ignored by default because it is slow and only tests test code. Run it with
    /// `cargo test -p core-crypto-keystore --lib timeout_guard -- --ignored`.
    #[test]
    #[ignore = "takes as long as the timeout it is verifying"]
    #[should_panic(expected = "deadlocked")]
    fn timeout_guard_actually_fires() {
        future::block_on(without_deadlock(async {
            Timer::after(TIMEOUT * 3).await;
        }));
    }

    /// With nothing in flight, `ensure_transaction` creates a transaction of its own and commits
    /// it once the operation succeeds.
    #[test]
    fn creates_and_commits_when_nothing_is_in_flight() {
        future::block_on(without_deadlock(async {
            let store = Database::open_in_memory().unwrap();

            store
                .ensure_transaction(async |tx| tx.save(consumer_data(OUTER)).await, std::convert::identity)
                .await
                .unwrap();

            // no transaction is in flight any more, so this can only be reading persisted data
            let persisted = store.get_unique::<ConsumerData>().await.unwrap().unwrap();
            assert_eq!(persisted.content, OUTER);
        }));
    }

    /// When a transaction is already in flight, `ensure_transaction` borrows it and leaves the
    /// commit to whoever owns it.
    #[test]
    fn borrows_an_in_flight_transaction_without_committing_it() {
        future::block_on(without_deadlock(async {
            let store = Database::open_in_memory().unwrap();
            let owned = store.new_transaction().await.unwrap();

            store
                .ensure_transaction(async |tx| tx.save(consumer_data(OUTER)).await, std::convert::identity)
                .await
                .unwrap();

            // the write landed in the in-flight transaction, so it is visible through the store ...
            let staged = store.get_unique::<ConsumerData>().await.unwrap().unwrap();
            assert_eq!(staged.content, OUTER);

            // ... but `ensure_transaction` must not have committed it: dropping the owner rolls the
            // write back, which would be impossible had it already been persisted.
            drop(owned);
            assert!(!store.exists::<ConsumerData>().await.unwrap());
        }));
    }

    /// A transaction which `ensure_transaction` created itself is rolled back when the operation
    /// fails, and the operation's own error is what comes back out.
    #[test]
    fn rolls_back_its_own_transaction_when_the_operation_fails() {
        future::block_on(without_deadlock(async {
            let store = Database::open_in_memory().unwrap();

            let error = store
                .ensure_transaction(
                    async |tx| {
                        tx.save(consumer_data(OUTER)).await?;
                        Err::<(), _>(TestError::Operation)
                    },
                    TestError::Keystore,
                )
                .await
                .unwrap_err();

            match error {
                TestError::Operation => {}
                TestError::Keystore(err) => panic!("expected the operation's own error, got a keystore error: {err}"),
            }
            assert!(!store.exists::<ConsumerData>().await.unwrap());
        }));
    }

    /// A nested `ensure_transaction` finds and reuses the transaction the outer call created.
    ///
    /// Regression test: an earlier implementation held the transaction mutex across the operation,
    /// so the nested call deadlocked against the outer one.
    #[test]
    fn can_be_nested() {
        future::block_on(without_deadlock(async {
            let store = Database::open_in_memory().unwrap();

            store
                .ensure_transaction(
                    async |tx| {
                        tx.save(consumer_data(OUTER)).await?;
                        store
                            .ensure_transaction(
                                async |nested| nested.save(consumer_data(NESTED)).await,
                                std::convert::identity,
                            )
                            .await?;
                        Ok(())
                    },
                    std::convert::identity,
                )
                .await
                .unwrap();

            // the nested call borrowed the outer transaction instead of creating its own, so both
            // writes committed together; `ConsumerData` is unique, so the later write is the survivor
            let persisted = store.get_unique::<ConsumerData>().await.unwrap().unwrap();
            assert_eq!(persisted.content, NESTED);
        }));
    }
}
