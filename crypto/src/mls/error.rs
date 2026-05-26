//! MLS errors

// We allow missing documentation in the error module because the types are generally self-descriptive.
#![allow(missing_docs)]

pub type Result<T, E = Error> = core::result::Result<T, E>;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The cipher suite identifier presented does not map to a known ciphersuite.
    #[error("Unknown cipher suite")]
    UnknownCipherSuite,
    #[error("Malformed or empty identifier found: {0}")]
    MalformedIdentifier(&'static str),
    #[error(transparent)]
    Keystore(#[from] crate::KeystoreError),
    #[error(transparent)]
    OpenMls(#[from] crate::OpenMlsError),
    #[error("{0}")]
    Leaf(#[from] crate::LeafError),
    #[error(transparent)]
    Recursive(#[from] crate::RecursiveError),
}
