use crate::{CryptoKeystoreResult, connection::ConnectionGuard};

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
#[derive(Clone, Copy, derive_more::From)]
pub enum Transactionlike<'a> {
    Rusqlite(&'a rusqlite::Transaction<'a>),
    Keystore(&'a crate::Transaction),
}

impl<'a, 'b> From<&'b Transactionlike<'a>> for Transactionlike<'b>
where
    'a: 'b,
{
    fn from(transaction: &'b Transactionlike<'a>) -> Self {
        *transaction
    }
}

impl<'a> Transactionlike<'a> {
    pub(crate) fn conn(&self) -> CryptoKeystoreResult<ConnectionGuard<'a>> {
        let guard = match self {
            Transactionlike::Rusqlite(transaction) => ConnectionGuard::Borrowed(transaction),
            Transactionlike::Keystore(transaction) => transaction.conn()?.into(),
        };
        Ok(guard)
    }
}
