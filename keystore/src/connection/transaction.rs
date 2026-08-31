//! The methods in this module handle keystore transactions.
//!
//! Keystore transactions are "fake", in-memory persistence of database operations over time.
//! They're required because actual [`rusqlite::Transaction`] is `!Send + !Sync`, and we need
//! `Send` at a minimum in order to keep the transaction around and manipulate it concurrently
//! from various tasks.

use std::{ops::Deref, sync::Arc};

use async_lock::MutexGuard;
use rusqlite::Connection;

use crate::{
    CryptoKeystoreError, CryptoKeystoreResult, Database, Transaction, UniqueArc, transaction::TransactionConnection,
    unique_arc::ArcWithReadGuard,
};

/// These impls control the keystore transaction lifecycle.
impl Database {
    /// Waits for the current transaction to be committed or rolled back, then starts a new one.
    ///
    /// With the `cross-process-lock` feature enabled, this also waits on transactions running
    /// against the same database in other processes.
    pub async fn new_transaction(self: &Arc<Self>) -> CryptoKeystoreResult<UniqueArc<Transaction>> {
        let lock_guard = self.transaction_lock.acquire().await?;
        Transaction::new(lock_guard, self.clone()).await
    }

    /// Start a new transaction if no other transaction is currently in progress.
    ///
    /// If a transaction is currently in progress, this will produce a `TransactionInProgress` error.
    /// With the `cross-process-lock` feature enabled, a transaction in progress in another process
    /// counts too.
    pub async fn try_new_immediate_transaction(self: &Arc<Self>) -> CryptoKeystoreResult<UniqueArc<Transaction>> {
        let lock_guard = self
            .transaction_lock
            .try_acquire()?
            .ok_or(CryptoKeystoreError::TransactionInProgress)?;
        Transaction::new(lock_guard, self.clone()).await
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
        let lock_guard = self.transaction_lock.acquire().await?;
        let transaction = Transaction::new(lock_guard, self.clone()).await?;

        let result = operation(&transaction).await;
        if result.is_ok() {
            transaction.commit().await?;
        } else {
            transaction.rollback().await?;
        }

        result
    }

    /// The connection on which to perform a database operation.
    ///
    /// When a transaction is in flight this is tha transaction's connection.
    /// Otherwise it is the database's internal connection.
    ///
    /// It is the caller's responsibility to ensure that mutating operations are only performed
    /// via a transaction!
    ///
    /// The returned type is deliberately `!Send` because there is an inner lock
    /// which is synchronous (for good reason, see field-level docs on `Transaction::conn`);
    /// holding that lock across an await point would wedge the database.
    pub(crate) async fn conn<'a>(&'a self) -> impl 'a + Deref<Target = Connection> {
        #[derive(derive_more::From)]
        enum ConnectionGuard<'a> {
            Transaction(TransactionConnection),
            Database(MutexGuard<'a, Connection>),
        }

        impl<'a> Deref for ConnectionGuard<'a> {
            type Target = Connection;

            fn deref(&self) -> &Self::Target {
                match self {
                    ConnectionGuard::Transaction(transaction_connection) => transaction_connection.deref(),
                    ConnectionGuard::Database(mutex_guard) => mutex_guard.deref(),
                }
            }
        }

        if let Some(weak) = self.transaction.lock().await.clone()
            && let Some(wrapper) = weak.upgrade_without_type_erasure().await
            && let Ok(transaction_connection) = TransactionConnection::shared(wrapper)
        {
            ConnectionGuard::from(transaction_connection)
        } else {
            self.conn.lock().await.into()
        }
    }

    /// Ensure a transaction exists, passing it to the operation.
    ///
    /// If a transaction is already in progress, perform the operation and pass on its result
    /// without affecting the transaction lifecycle at all, whether or not the operation succeeded.
    ///
    /// NOTE: if the transaction was already in progress, its owner's `.commit()` will block until
    /// the operation here has completed.
    ///
    /// If a transaction was _not_ already in progress, create one and then perform the operation.
    /// If the operation succeeded, commit the transaction; otherwise, roll it back.
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
    /// complete before it can acquire the transaction lock. This might be surprising, but isn't
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

        if let TxHandle::Owned(tx) = handle {
            if result.is_ok() {
                tx.commit().await.map_err(&map_err)?;
            } else {
                tx.rollback().await.map_err(&map_err)?;
            }
        }

        result
    }
}
