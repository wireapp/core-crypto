//! MLS errors

// We allow missing documentation in the error module because the types are generally self-descriptive.
#![allow(missing_docs)]

pub type Result<T, E = Error> = core::result::Result<T, E>;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Supplied user id was not valid")]
    InvalidUserId,
    #[error("X509 certificate bundle set was empty")]
    NoX509CertificateBundle,
    #[error("Tried to insert an already existing CredentialBundle")]
    CredentialBundleConflict,
    #[error("A MLS operation was requested but MLS hasn't been initialized on this instance")]
    MlsNotInitialized,
    #[error("A Credential of type {0:?} was not found locally which is very likely an implementation error")]
    CredentialNotFound(crate::prelude::MlsCredentialType),
    #[error("supplied signature scheme was not valid")]
    InvalidSignatureScheme,
    #[error("End-to-end identity enrollment has not been done")]
    E2eiEnrollmentNotDone,
    // This uses a `Box<dyn>` pattern because we do not directly import `keystore` from here right now,
    // and it feels a bit silly to add the dependency only for this.
    #[error("{context}")]
    Keystore {
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
        context: &'static str,
    },
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
    #[error("Keypackage list was empty")]
    EmptyKeypackageList,
    #[error("Computing keypackage hashref")]
    ComputeKeypackageHashref(#[source] openmls::error::LibraryError),
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
    #[error("Generating random client id")]
    GenerateRandomClientId(#[source] mls_crypto_provider::MlsProviderError),
    #[error(
        r#"The externally-generated client ID initialization cannot continue - there's no provisional keypair in-store!

        Have you called `CoreCrypto::generate_raw_keypair` ?"#
    )]
    NoProvisionalIdentityFound,
    /// This error occurs when during the MLS external client generation, we end up with more than one client identity in store.
    ///
    /// This is usually not possible, unless there's some kind of concurrency issue
    /// on the consumer (creating an ext-gen client AND a normal one at the same time for instance)
    #[error(
        "Somehow CoreCrypto holds more than one MLS identity. Something might've gone very wrong with this client!"
    )]
    TooManyIdentitiesPresent,
    #[error("The supplied credential does not match the id or signature schemes provided")]
    WrongCredential,
    #[error("Generating signature keypair")]
    GeneratingSignatureKeypair(#[source] openmls_traits::types::CryptoError),
    #[error("The MLS group is in an invalid state for an unknown reason")]
    InternalMlsError,
    #[error("{context}")]
    Conversation {
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
    Root {
        context: &'static str,
        #[source]
        source: Box<crate::Error>,
    },
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

    pub(crate) fn tls_serialize(item: &'static str) -> impl FnOnce(tls_codec::Error) -> Self {
        move |source| Self::TlsSerialize { item, source }
    }

    pub(crate) fn tls_deserialize(item: &'static str) -> impl FnOnce(tls_codec::Error) -> Self {
        move |source| Self::TlsDeserialize { item, source }
    }

    pub(crate) fn conversation(context: &'static str) -> impl FnOnce(crate::mls::conversation::Error) -> Self {
        move |source| Self::Conversation {
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

    pub(crate) fn root(context: &'static str) -> impl FnOnce(crate::Error) -> Self {
        move |source| Self::Root {
            context,
            source: Box::new(source),
        }
    }
}
