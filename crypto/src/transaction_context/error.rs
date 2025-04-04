// We allow missing documentation in the error module because the types are generally self-descriptive.
#![allow(missing_docs)]

use crate::mls::conversation::pending_conversation::PendingConversation;

use super::e2e_identity;

/// A module-specific [Result][core::result::Result] type with a default error variant.
pub type Result<T, E = Error> = core::result::Result<T, E>;

/// Errors produced during a transaction
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("caller error: {0}")]
    CallerError(&'static str),
    #[error("This transaction context has already been finished and can no longer be used.")]
    InvalidTransactionContext,
    #[error("The conversation with the specified id is pending")]
    PendingConversation(PendingConversation),
    #[error("Couldn't find client")]
    ClientNotFound(crate::prelude::ClientId),
    #[error("Serializing {item} for TLS")]
    TlsSerialize {
        item: &'static str,
        #[source]
        source: tls_codec::Error,
    },
    #[error("Deserializing {item} for TLS")]
    TlsDeserialize {
        item: &'static str,
        #[source]
        source: tls_codec::Error,
    },
    #[error(transparent)]
    E2EIdentity(#[from] e2e_identity::Error),
    #[error(transparent)]
    Keystore(#[from] crate::KeystoreError),
    #[error(transparent)]
    Mls(#[from] crate::MlsError),
    #[error("{0}")]
    Leaf(#[from] crate::LeafError),
    #[error(transparent)]
    Recursive(#[from] crate::RecursiveError),
}

impl Error {
    pub fn tls_serialize(item: &'static str) -> impl FnOnce(tls_codec::Error) -> Self {
        move |source| Self::TlsSerialize { item, source }
    }

    pub fn tls_deserialize(item: &'static str) -> impl FnOnce(tls_codec::Error) -> Self {
        move |source| Self::TlsDeserialize { item, source }
    }
}
