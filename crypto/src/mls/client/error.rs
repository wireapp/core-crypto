//! MLS errors

// We allow missing documentation in the error module because the types are generally self-descriptive.
#![allow(missing_docs)]

pub(crate) type Result<T, E = Error> = core::result::Result<T, E>;

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
    #[error("Keypackage list was empty")]
    EmptyKeypackageList,
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
}
