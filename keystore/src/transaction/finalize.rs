//! Methods which terminate the lifecycle of a [`TransactionWrapper`]

use rusqlite::Connection;

use super::{GUARD_EXPECTATION, Transaction};
use crate::{CryptoKeystoreError, CryptoKeystoreResult, UniqueArc};

impl Transaction {
    /// Execute rollback. Abstracted here because there are two paths to this destination.
    fn execute_rollback(conn: &Connection) -> CryptoKeystoreResult<()> {
        if !Self::is_active(conn) {
            return Ok(());
        }

        let mut stmt = conn.prepare_cached("ROLLBACK TRANSACTION")?;
        // rollback doesn't tell us how many rows were changed, so ignore it
        stmt.execute([])?;

        Ok(())
    }
}

impl UniqueArc<Transaction> {
    /// Consume this arc-wrapper and drop the internal transaction, first performing an operation
    /// on the connection.
    async fn consume(
        self,
        operation: impl FnOnce(&Connection) -> CryptoKeystoreResult<()>,
    ) -> CryptoKeystoreResult<()> {
        // We're doing a little dance here, which is tricky but legal: this statement
        // _consumes_ the `UniqueArc` which is `self`, but
        // _borrows_ the `TransactionWrapper` contained in there. That struct impls `Drop`,
        // which means it can't be consumably destructured like this, but because we know
        // we have the only arc reference, we know it's going to run its destructor as soon
        // as this function ends.
        let Transaction {
            ref database,
            ref mut conn,
            ..
        } = UniqueArc::into_inner(self).await;

        // clear the weak reference to this transaction
        *database.transaction.lock().await = None;

        // locking here is guaranteed not to block because we consumed the unique arc; there are no other
        // live references to the data
        let mut guard = conn.lock();

        // we need to ensure we only actually clear the connection (preventing rollback)
        // after we know the operation succeeded. Otherwise if something in this block errors,
        // the transaction doesn't get rolled back and no new transaction can ever be created
        {
            let conn = guard.as_ref().expect(GUARD_EXPECTATION);
            operation(conn)?;
        }
        let _ = guard.take();

        Ok(())
    }

    /// Persists all the operations in the database.
    pub async fn commit(self) -> Result<(), CryptoKeystoreError> {
        self.consume(|conn| {
            let mut stmt = conn.prepare_cached("COMMIT TRANSACTION")?;
            stmt.execute([])?;
            Ok(())
        })
        .await
    }

    /// Roll back this transaction in the database.
    ///
    /// There are two differences between manual rollback and implicit:
    ///
    /// - manual rollback clears the database's weak transaction ref
    /// - manual rollback permits propagation of db-level errors
    pub async fn rollback(self) -> CryptoKeystoreResult<()> {
        self.consume(Transaction::execute_rollback).await
    }
}

impl Drop for Transaction {
    fn drop(&mut self) {
        // a dropped wrapper has rollback behavior, but we can't clear the weak arc
        // in the database. that's fine, that's why it was weak in the first place.

        // locking here is guaranteed not to wait because this is `Drop`; the strong count is 0
        if let Some(conn) = self.conn.lock().take() {
            // we have to just kind of hope for the best here
            let _ = Self::execute_rollback(&conn);
        }
    }
}
