use std::ops::Deref;

use rusqlite::Connection;

use crate::{CryptoKeystoreResult, transaction::TransactionConnection};

/// A guard unifying the types of connection provided by [`Transactionlike`].
#[derive(derive_more::From)]
pub(crate) enum ConnectionGuard<'a> {
    Rusqlite(&'a rusqlite::Transaction<'a>),
    Keystore(TransactionConnection),
}

impl<'a> Deref for ConnectionGuard<'a> {
    type Target = Connection;

    fn deref(&self) -> &Self::Target {
        match self {
            ConnectionGuard::Rusqlite(transaction) => (*transaction).deref(),
            ConnectionGuard::Keystore(transaction_connection) => transaction_connection.deref(),
        }
    }
}

/// A transaction which might come from our own keystore implementation, or directly from rusqlite.
///
/// We want type-level assurance that all database mutation occurs within the scope of a transaction,
/// but it doesn't really matter if the transaction type is our own or provided by rusqlite.
/// There are use cases for both:
///
/// - within a migration, it's simpler to use a rusqlite transaction
/// - for general usage, our transaction implementation works better in a long-lived async context
///
/// This type generalizes over borrowed instances of each.
#[derive(derive_more::From)]
pub enum Transactionlike<'a> {
    Rusqlite(&'a rusqlite::Transaction<'a>),
    Keystore(&'a crate::Transaction),
}

impl<'a> Transactionlike<'a> {
    pub(crate) fn conn(&self) -> CryptoKeystoreResult<ConnectionGuard<'a>> {
        let guard = match self {
            Transactionlike::Rusqlite(transaction) => (*transaction).into(),
            Transactionlike::Keystore(transaction) => transaction.conn()?.into(),
        };
        Ok(guard)
    }
}
