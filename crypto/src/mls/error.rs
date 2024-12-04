//! MLS errors

// We allow missing documentation in the error module because the types are generally self-descriptive.
#![allow(missing_docs)]

use crate::LeafError;

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
    // This uses a `Box<dyn>` pattern because we do not directly import `keystore` from here right now,
    // and it feels a bit silly to add the dependency only for this.
    #[error("{context}")]
    Keystore {
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
        context: &'static str,
    },
    #[error("{context}")]
    MlsOperation {
        context: &'static str,
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },
    #[error("{context}")]
    MlsClient {
        context: &'static str,
        #[source]
        source: Box<crate::mls::client::Error>,
    },
    #[error("{context}")]
    MlsConversation {
        context: &'static str,
        #[source]
        source: Box<crate::mls::conversation::Error>,
    },
    #[error("{context}")]
    MlsCredential {
        context: &'static str,
        #[source]
        source: Box<crate::mls::credential::Error>,
    },
    #[error("{context}")]
    E2e {
        context: &'static str,
        #[source]
        source: Box<crate::e2e_identity::Error>,
    },
    #[error("{context}")]
    Root {
        context: &'static str,
        #[source]
        source: Box<crate::Error>,
    },
    #[error(transparent)]
    Leaf(#[from] LeafError),
}

impl Error {
    pub(crate) fn keystore<E>(context: &'static str) -> impl FnOnce(E) -> Self
    where
        E: 'static + std::error::Error + Send + Sync,
    {
        move |err| Self::Keystore {
            context,
            source: Box::new(err),
        }
    }

    pub(crate) fn mls_operation<E>(context: &'static str) -> impl FnOnce(E) -> Self
    where
        E: 'static + std::error::Error + Send + Sync,
    {
        move |source| Self::MlsOperation {
            context,
            source: Box::new(source),
        }
    }

    pub(crate) fn client(context: &'static str) -> impl FnOnce(crate::mls::client::Error) -> Self {
        move |source| Self::MlsClient {
            context,
            source: Box::new(source),
        }
    }

    pub(crate) fn conversation(context: &'static str) -> impl FnOnce(crate::mls::conversation::Error) -> Self {
        move |source| Self::MlsConversation {
            context,
            source: Box::new(source),
        }
    }

    pub(crate) fn credential(context: &'static str) -> impl FnOnce(crate::mls::credential::Error) -> Self {
        move |source| Self::MlsCredential {
            context,
            source: Box::new(source),
        }
    }

    pub(crate) fn e2e(context: &'static str) -> impl FnOnce(crate::e2e_identity::Error) -> Self {
        move |source| Self::E2e {
            context,
            source: Box::new(source),
        }
    }

    pub(crate) fn root(context: &'static str) -> impl FnOnce(crate::Error) -> Self {
        move |source| Self::Root {
            context,
            source: Box::new(source),
        }
    }
}
