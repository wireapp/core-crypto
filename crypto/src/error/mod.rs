mod cryptobox_migration;
mod keystore;
mod leaf;
mod mls;
mod proteus;
mod recursive;
mod wrapper;

pub use cryptobox_migration::{CryptoboxMigrationError, CryptoboxMigrationErrorKind};
pub use keystore::KeystoreError;
pub use leaf::LeafError;
pub use mls::{MlsError, MlsErrorKind};
pub use proteus::{ProteusError, ProteusErrorKind};
pub use recursive::{RecursiveError, ToRecursiveError};
pub(crate) use wrapper::WrappedContextualError;

/// A module-specific [Result][core::result::Result] type with a default error variant.
pub type Result<T, E = Error> = core::result::Result<T, E>;

/// Errors produced by the root module group
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Invalid [crate::transaction_context::TransactionContext]. This context has been finished and can no longer be used.
    #[error("This transaction context has already been finished and can no longer be used.")]
    InvalidTransactionContext,
    /// The proteus client has been called but has not been initialized yet
    #[error("Proteus client hasn't been initialized")]
    ProteusNotInitialized,
    /// Mls Transport Callbacks were not provided
    #[error("The mls transport callbacks needed for CoreCrypto to operate were not set")]
    MlsTransportNotProvided,
    /// Any error that occurs during mls transport.
    #[error("Error during mls transport: {0}")]
    ErrorDuringMlsTransport(String),
    /// This item requires a feature that the core-crypto library was built without
    #[error("This item requires a feature that the core-crypto library was built without: {0}")]
    FeatureDisabled(&'static str),
    /// A key store operation failed
    #[error(transparent)]
    Keystore(#[from] KeystoreError),
    /// An external MLS operation failed
    #[error(transparent)]
    Mls(#[from] MlsError),
    /// A Proteus operation failed
    #[error(transparent)]
    Proteus(#[from] ProteusError),
    /// A cryptobox migration operation failed
    #[error(transparent)]
    CryptoboxMigration(#[from] CryptoboxMigrationError),
    /// A crate-internal operation failed
    #[error(transparent)]
    Recursive(#[from] RecursiveError),
}

/// Produce the error message from the innermost wrapped error.
///
/// We produce arbitrarily nested errors which are very helpful
/// at capturing relevant context, and very bad at surfacing the
/// root error cause in a default `.to_string()` call.
///
/// This trait, automatically implemented for all standard errors,
/// rectifies this problem.
pub trait InnermostErrorMessage {
    /// Produce the error message from the innermost wrapped error.
    fn innermost_error_message(&self) -> String;
}

impl<E: std::error::Error> InnermostErrorMessage for E {
    fn innermost_error_message(&self) -> String {
        let mut err: &dyn std::error::Error = self;
        while let Some(source) = err.source() {
            err = source;
        }
        err.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn can_unpack_wrapped_error() {
        let inner = Error::InvalidTransactionContext;
        let outer = RecursiveError::root("wrapping the inner for test purposes")(inner);
        let message = outer.innermost_error_message();
        assert_eq!(message, Error::InvalidTransactionContext.to_string());
    }
}
