//! MLS errors

// We allow missing documentation in the error module because the types are generally self-descriptive.
#![allow(missing_docs)]

pub type Result<T, E = Error> = core::result::Result<T, E>;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The cipher suite identifier presented does not map to a known ciphersuite.
    #[error("Unknown cipher suite")]
    UnknownCipherSuite,
    #[error(transparent)]
    OpenMls(#[from] crate::OpenMlsError),
    #[error(transparent)]
    Recursive(#[from] crate::RecursiveError),
}
