//! MLS errors

// We allow missing documentation in the error module because the types are generally self-descriptive.
#![allow(missing_docs)]

pub type Result<T, E = Error> = core::result::Result<T, E>;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Couldn't find client")]
    ClientNotFound(crate::prelude::ClientId),
    #[error(
        "You tried to join with an external commit but did not merge it yet. We will reapply this message for you when you merge your external commit"
    )]
    UnmergedPendingGroup,
    /// The ciphersuite identifier presented does not map to a known ciphersuite.
    #[error("Unknown ciphersuite")]
    UnknownCiphersuite,
    #[error("The callbacks needed for CoreCrypto to operate were not set")]
    CallbacksNotSet,
    #[error("External add proposal validation failed: only users already in the group are allowed")]
    UnauthorizedExternalAddProposal,
    #[error("External Commit sender was not authorized to perform such")]
    UnauthorizedExternalCommit,
    #[error("Malformed or empty identifier found: {0}")]
    MalformedIdentifier(&'static str),
    #[error(transparent)]
    Keystore(#[from] crate::KeystoreError),
    #[error("{context}")]
    MlsOperation {
        context: &'static str,
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },
    #[error(transparent)]
    Leaf(#[from] crate::LeafError),
    #[error(transparent)]
    Recursive(#[from] crate::RecursiveError),
}

impl Error {
    pub(crate) fn mls_operation<E>(context: &'static str) -> impl FnOnce(E) -> Self
    where
        E: 'static + std::error::Error + Send + Sync,
    {
        move |source| Self::MlsOperation {
            context,
            source: Box::new(source),
        }
    }
}
