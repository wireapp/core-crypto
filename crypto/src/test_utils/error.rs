// We allow missing documentation in the error module because the types are generally self-descriptive.
#![allow(missing_docs)]

pub type Result<T, E = Error> = core::result::Result<T, E>;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("this was not supposed to happen")]
    ImplementationError,
    #[error(transparent)]
    Mls(#[from] crate::MlsError),
    #[error(transparent)]
    Keystore(#[from] crate::KeystoreError),
    #[error("{0}")]
    Leaf(#[from] crate::LeafError),
    #[error(transparent)]
    Recursive(#[from] crate::RecursiveError),
}
