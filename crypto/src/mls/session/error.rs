//! MLS errors

// We allow missing documentation in the error module because the types are generally self-descriptive.
#![allow(missing_docs)]

use openmls::prelude::SignatureScheme;

use crate::ConversationId;

pub(crate) type Result<T, E = Error> = core::result::Result<T, E>;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Supplied user id was not valid")]
    InvalidUserId,
    #[error("X509 certificate bundle set was empty")]
    NoX509CertificateBundle,
    #[error("credentials must be distinct in signature scheme, credential type, and earliest validity timestamp")]
    CredentialConflict,
    #[error("A MLS operation was requested but MLS hasn't been initialized on this instance")]
    MlsNotInitialized,
    #[error("No credential of type ({0:?}, {1:?}) was found in this session")]
    CredentialNotFound(crate::CredentialType, SignatureScheme),
    #[error("supplied signature scheme was not valid")]
    InvalidSignatureScheme,
    /// The keystore has no knowledge of such client; this shouldn't happen as Client::init is failsafe (find-else-create)
    #[error("The provided client signature has not been found in the keystore")]
    ClientSignatureNotFound,
    /// Client was unexpectedly ready.
    ///
    /// This indicates an invalid calling pattern.
    #[error("Client was unexpectedly ready")]
    UnexpectedlyReady,
    #[error("The keystore already contains a stored identity. Cannot create a new one!")]
    IdentityAlreadyPresent,
    #[error("The supplied credential does not match the id this CC instance was initialized with")]
    WrongCredential,
    #[error("Credentials of type {0} are unknown")]
    UnknownCredential(u16),
    #[error("this credential is still in use by the conversation with id \"{}\"", hex::encode(.0))]
    CredentialStillInUse(ConversationId),
    #[error("An EpochObserver has already been registered; reregistration is not possible")]
    EpochObserverAlreadyExists,
    #[error("An HistoryHandler has already been registered; reregistration is not possible")]
    HistoryObserverAlreadyExists,
    #[error("something went wrong when generating and storing a new keypackage: {0}")]
    KeypackageNew(String),
    #[error("This credential ref matched more than a single credential in the keystore")]
    AmbiguousCredentialRef,
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
    Mls(#[from] crate::MlsError),
    #[error(transparent)]
    Keystore(#[from] crate::KeystoreError),
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

    pub fn keypackage_new<E: std::error::Error>() -> impl FnOnce(E) -> Self {
        move |source| Self::KeypackageNew(source.to_string())
    }
}
