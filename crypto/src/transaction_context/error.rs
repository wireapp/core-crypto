use super::e2e_identity;

/// A module-specific [Result][core::result::Result] type with a default error variant.
pub type Result<T, E = Error> = core::result::Result<T, E>;

/// Errors produced during a transaction
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Invalid [crate::transaction_context::TransactionContext]. This context has been finished and can no longer be used.
    #[error("This transaction context has already been finished and can no longer be used.")]
    InvalidTransactionContext,
    /// An E2E-Identity operation failed
    #[error(transparent)]
    E2EIdentity(#[from] e2e_identity::Error),
    /// A keystore operation failed
    #[error(transparent)]
    Keystore(#[from] crate::KeystoreError),
    #[error(transparent)]
    /// An MLS operation failed
    Mls(#[from] crate::MlsError),
    /// A crate-internal operation failed
    #[error(transparent)]
    Recursive(#[from] crate::RecursiveError),
}
