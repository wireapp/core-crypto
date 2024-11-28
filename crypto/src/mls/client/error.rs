//! MLS errors

pub type Result<T, E = Error> = core::result::Result<T, E>;

/// MLS client errors
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Supplied user id was not valid")]
    InvalidUserId,
    #[error("X509 certificate bundle set was empty")]
    NoX509CertificateBundle,
    /// Tried to insert an already existing CredentialBundle
    #[error("Tried to insert an already existing CredentialBundle")]
    CredentialBundleConflict,
    /// A MLS operation was requested but MLS hasn't been initialized on this instance
    #[error("A MLS operation was requested but MLS hasn't been initialized on this instance")]
    MlsNotInitialized,
    /// A Credential was not found locally which is very likely an implementation error
    #[error("A Credential of type {0:?} was not found locally which is very likely an implementation error")]
    CredentialNotFound(crate::prelude::MlsCredentialType),
    /// A key store operation failed
    //
    // This uses a `Box<dyn>` pattern because we do not directly import `keystore` from here right now,
    // and it feels a bit silly to add the dependency only for this.
    #[error("{context}")]
    Keystore {
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
        context: &'static str,
    },
    /// Serializing an item for tls
    #[error("Serializing {item} for TLS")]
    TlsSerialize {
        item: &'static str,
        #[source]
        source: tls_codec::Error,
    },
    /// Deserializing an item for tls
    #[error("Deserializing {item} for TLS")]
    TlsDeserialize {
        item: &'static str,
        #[source]
        source: tls_codec::Error,
    },
    /// Keypackage list was empty
    #[error("Keypackage list was empty")]
    EmptyKeypackageList,
    /// Computing Keypackage Hashref
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
    /// The keystore already has a stored identity. As such, we cannot create a new raw identity
    #[error("The keystore already contains a stored identity. Cannot create a new one!")]
    IdentityAlreadyPresent,
    /// Generating random client id
    #[error("Generating random client id")]
    GenerateRandomClientId(#[source] mls_crypto_provider::MlsProviderError),
    /// This error occurs when we cannot find any provisional keypair in the store, indicating that the `generate_raw_keypair` method hasn't been called.
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
    /// The supplied credential does not match the id or signature schemes provided.
    #[error("The supplied credential does not match the id or signature schemes provided")]
    WrongCredential,
    /// Generating signature keypair
    #[error("Generating signature keypair")]
    GeneratingSignatureKeypair(#[source] openmls_traits::types::CryptoError),
    /// Compatibility wrapper
    ///
    /// This should be removed before merging this branch, but it allows an easier migration path to module-specific errors.
    #[deprecated]
    #[error(transparent)]
    CryptoError(Box<crate::CryptoError>),
}

impl From<crate::CryptoError> for Error {
    fn from(value: crate::CryptoError) -> Self {
        Self::CryptoError(Box::new(value))
    }
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
}
