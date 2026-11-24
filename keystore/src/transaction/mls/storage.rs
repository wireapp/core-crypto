//! The [`Storage`] type, and the ways it reaches the tables.

use crate::{
    CryptoKeystoreError, CryptoKeystoreResult, Database, Transaction, Transactionlike, connection::ConnectionGuard,
};

/// openmls's storage: our tables, reached through a transaction or, read-only, through the database.
pub type MlsStorage<'a> = Storage<MlsStorageAccess<'a>>;

/// openmls's storage, for a migration, on the transaction the migration runs in.
///
/// This is a type of its own, not another kind of [`Access`], because a `rusqlite::Transaction` can't be shared
/// between threads. Holding one would keep [`MlsStorage`], and every future that holds it, from being `Send`.
pub(crate) type MigrationStorage<'a> = Storage<&'a rusqlite::Transaction<'a>>;

/// openmls's storage, on top of our tables, accessed through `A`.
#[derive(Clone, Copy)]
pub struct Storage<A>(A);

/// How [`MlsStorage`] reaches the tables.
#[derive(Clone, Copy)]
pub enum MlsStorageAccess<'a> {
    /// Read from and write to this transaction.
    Transaction(&'a Transaction),
    /// Read through the database, which reads through the transaction in flight if there is one.
    ///
    /// Reads never wait for a lock. If one is held, for example while a transaction is being committed, they fail
    /// with [`CryptoKeystoreError::Busy`]. Writes fail with
    /// [`CryptoKeystoreError::MutatingOperationWithoutTransaction`].
    ReadOnly(&'a Database),
}

impl<'a> From<&'a Transaction> for MlsStorage<'a> {
    fn from(transaction: &'a Transaction) -> Self {
        Storage(MlsStorageAccess::Transaction(transaction))
    }
}

impl<'a> MlsStorage<'a> {
    /// Storage that reads through the database, and can't be written to.
    pub fn read_only(database: &'a Database) -> Self {
        Storage(MlsStorageAccess::ReadOnly(database))
    }
}

/// A connection to read openmls's storage through, held until it is dropped.
///
/// Unlike [`MlsStorage::read_only`], which fails while the database is busy, getting this waits for the connection.
/// It holds a lock on the database until it is dropped, so don't hold it across an `await`.
pub struct MlsReadConnection<'a>(ConnectionGuard<'a>);

impl Database {
    /// Wait for a connection to read openmls's storage through.
    ///
    /// Reads through it see the writes of a transaction in flight.
    pub async fn mls_read_connection(&self) -> MlsReadConnection<'_> {
        MlsReadConnection(self.conn().await)
    }
}

impl MlsReadConnection<'_> {
    /// openmls's storage, reading through this connection. Writes fail with
    /// [`CryptoKeystoreError::MutatingOperationWithoutTransaction`].
    pub fn storage(&self) -> Storage<&rusqlite::Connection> {
        Storage(&self.0)
    }
}

impl<'a> From<&'a rusqlite::Transaction<'a>> for MigrationStorage<'a> {
    fn from(transaction: &'a rusqlite::Transaction<'a>) -> Self {
        Storage(transaction)
    }
}

/// Something [`Storage`] can reach the tables through.
pub(crate) trait Access<'a> {
    /// The transaction to write to.
    fn transaction(&self) -> CryptoKeystoreResult<Transactionlike<'a>>;
    /// A connection to read from.
    fn read_conn(&self) -> CryptoKeystoreResult<ConnectionGuard<'a>> {
        self.transaction()?.conn()
    }
}

impl<'a> Access<'a> for MlsStorageAccess<'a> {
    fn transaction(&self) -> CryptoKeystoreResult<Transactionlike<'a>> {
        match self {
            Self::Transaction(transaction) => Ok((*transaction).into()),
            Self::ReadOnly(_) => Err(CryptoKeystoreError::MutatingOperationWithoutTransaction),
        }
    }

    fn read_conn(&self) -> CryptoKeystoreResult<ConnectionGuard<'a>> {
        match self {
            Self::Transaction(_) => self.transaction()?.conn(),
            Self::ReadOnly(database) => database.try_conn(),
        }
    }
}

impl<'a> Access<'a> for &'a rusqlite::Transaction<'a> {
    fn transaction(&self) -> CryptoKeystoreResult<Transactionlike<'a>> {
        Ok((*self).into())
    }
}

impl<'a> Access<'a> for &'a rusqlite::Connection {
    fn transaction(&self) -> CryptoKeystoreResult<Transactionlike<'a>> {
        Err(CryptoKeystoreError::MutatingOperationWithoutTransaction)
    }

    fn read_conn(&self) -> CryptoKeystoreResult<ConnectionGuard<'a>> {
        Ok(ConnectionGuard::Borrowed(self))
    }
}

#[expect(private_bounds, reason = "the methods here are private too")]
impl<'a, B: Access<'a>> Storage<B> {
    pub(super) fn transaction(&self) -> CryptoKeystoreResult<Transactionlike<'a>> {
        self.0.transaction()
    }

    pub(super) fn write_conn(&self) -> CryptoKeystoreResult<ConnectionGuard<'a>> {
        self.transaction()?.conn()
    }

    pub(super) fn read_conn(&self) -> CryptoKeystoreResult<ConnectionGuard<'a>> {
        self.0.read_conn()
    }
}
