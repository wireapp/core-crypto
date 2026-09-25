use std::ops::Deref;

use async_lock::MutexGuardArc;
use parking_lot::{ArcMutexGuard, RawMutex};
use rusqlite::Connection;

use super::{GUARD_EXPECTATION, Transaction};
use crate::{CryptoKeystoreError, CryptoKeystoreResult, unique_arc::ArcWithReadGuard};

/// The type of the guard we end up holding over the connection.
type InternalGuard = ArcMutexGuard<RawMutex, Option<MutexGuardArc<crate::connection::ManagedConnection>>>;
/// Keeps the wrapper alive for as long as this guard exists. `None` when the caller
/// already holds a `&TransactionWrapper`, where borrowck provides the same guarantee.
/// `Some` when the caller upgraded a weak reference; this holds the reference for the
/// duration that this connection is held, ensuring that it stays alive.
type Keepalive = Option<ArcWithReadGuard<Transaction>>;

/// A guard over the connection belonging to an in-flight transaction.
///
/// Derefs to the [`Connection`] on which `BEGIN IMMEDIATE` was issued, so reads through it
/// see the transaction's uncommitted writes and writes through it join the transaction.
///
/// Field order is load-bearing, for the same reason as [`ArcWithReadGuard`]: `guard` must be
/// released before `_keepalive`. Were `_keepalive` to drop first it could drop the wrapper's
/// last strong reference, and `TransactionWrapper::drop` would then block trying to lock a
/// mutex we still hold.
pub struct TransactionConnection {
    guard: InternalGuard,
    _sqlite: crate::connection::SqliteGuard,
    _keepalive: Keepalive,
}

impl TransactionConnection {
    /// Construct this transaction connection, checking that the transaction is in fact still alive.
    fn new(
        guard: InternalGuard,
        keepalive: Keepalive,
        sqlite: crate::connection::SqliteGuard,
    ) -> CryptoKeystoreResult<Self> {
        let connection = Self {
            guard,
            _sqlite: sqlite,
            _keepalive: keepalive,
        };
        // Construct first so field order also releases locks before the keepalive
        // on the error path.
        if !Transaction::is_active(&connection) {
            return Err(CryptoKeystoreError::UnexpectedRollback);
        }
        Ok(connection)
    }
}

impl Deref for TransactionConnection {
    type Target = Connection;

    fn deref(&self) -> &Connection {
        self.guard.as_ref().expect(GUARD_EXPECTATION)
    }
}

impl Transaction {
    /// Guard over this transaction's connection.
    ///
    /// Errors if SQLite has already rolled this transaction back under us.
    pub fn conn(&self) -> CryptoKeystoreResult<TransactionConnection> {
        let sqlite = crate::connection::SqliteGuard::lock();
        TransactionConnection::new(self.conn.lock_arc(), None, sqlite)
    }
}

impl TransactionConnection {
    /// As [`TransactionWrapper::conn`], for callers who reached the transaction
    /// through a weak reference and must keep it alive.
    pub(crate) fn shared(wrapper: ArcWithReadGuard<Transaction>) -> CryptoKeystoreResult<Self> {
        let sqlite = crate::connection::SqliteGuard::lock();
        let guard = wrapper.conn.lock_arc();
        Self::new(guard, Some(wrapper), sqlite)
    }
}
