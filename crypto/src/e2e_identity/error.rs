//! End to end identity errors

use crate::prelude::MlsCredentialType;
use core_crypto_keystore::CryptoKeystoreError;

/// Wrapper over a [Result][core::result::Result] of an end to end identity error
pub type Result<T, E = Error> = core::result::Result<T, E>;

/// End to end identity errors
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Client misused this library
    #[error("Incorrect usage of this API")]
    ImplementationError,
    /// Incoming support
    #[error("Not yet supported")]
    NotYetSupported,
    /// The required local MLS client was not initialized. It's likely a consumer error
    #[error("Expected a MLS client with credential type {0:?} but none found")]
    MissingExistingClient(MlsCredentialType),
    /// Enrollment methods are called out of order
    #[error("Enrollment methods are called out of order: {0}")]
    OutOfOrderEnrollment(&'static str),
    /// Invalid OIDC RefreshToken supplied
    #[error("Invalid OIDC RefreshToken supplied")]
    InvalidRefreshToken,
    /// An error occurred while trying to persist the RefreshToken in the keystore
    #[error("An error occurred while trying to persist the RefreshToken in the keystore")]
    KeyStoreError(#[from] CryptoKeystoreError),
    /// Error creating client Dpop token or acme error
    #[error(transparent)]
    IdentityError(#[from] wire_e2e_identity::prelude::E2eIdentityError),
    /// Error validating X509 parameters
    #[error(transparent)]
    X509Error(#[from] wire_e2e_identity::prelude::x509::RustyX509CheckError),
    /// Error parsing a URL
    #[error(transparent)]
    UrlError(#[from] url::ParseError),
    /// Json error
    #[error(transparent)]
    JsonError(#[from] serde_json::Error),
    /// We already have an ACME Root Trust Anchor registered. Cannot proceed but this is usually indicative of double registration and can be ignored
    #[error("We already have an ACME Root Trust Anchor registered. Cannot proceed but this is usually indicative of double registration and can be ignored")]
    TrustAnchorAlreadyRegistered,
    /// Getting MLS ratchet tree
    #[error("Getting MLS ratchet tree")]
    MlsRatchetTree(#[from] openmls::messages::group_info::GroupInfoError),
    /// Generating signature key
    #[error("Generating signature key")]
    SignatureKeyGen(#[source] openmls_traits::types::CryptoError),
    #[error("Normalizing ed25519 key")]
    /// Normalizing ed25519 key
    NormalizingEd25519Key(#[source] openmls_traits::types::CryptoError),
    #[error("Generating new PKI keypair")]
    /// Generating new PKi keypair
    GeneratePkiKeypair(#[from] mls_crypto_provider::MlsProviderError),
    /// The encountered ClientId does not match Wire's definition
    #[error("The encountered ClientId does not match Wire's definition")]
    InvalidClientId,
    /// see [`x509_cert::der::Error`]
    #[error(transparent)]
    X509CertDerError(#[from] x509_cert::der::Error),
    /// This function accepts a list of IDs as a parameter, but that list was empty
    #[error("This function accepts a list of IDs as a parameter, but that list was empty")]
    EmptyInputIdList,
    /// Getting user identities
    #[error("Getting user identities")]
    GetUserIdentities(#[source] crate::mls::client::error::Error),
    /// PKI environment must ben set before calling this function
    #[error("PKI Environment must be set before calling this function")]
    PkiEnvironmentUnset,
    /// Computing key package hash ref
    #[error("Computing key package hash ref")]
    KeyPackageHashRef(#[from] openmls::error::LibraryError),
    /// Serializing key package for TLS
    #[error("Serializing key package for TLS")]
    TlsSerializingKeyPackage(#[from] tls_codec::Error),
    /// The MLS group is in an invalid state for an unknown reason
    #[error("The MLS group is in an invalid state for an unknown reason")]
    InternalMlsError,
    /// Something in certificate validation went wrong
    #[error("{context}: {upstream}")]
    CertificateValidation {
        /// What was happening when the error was thrown
        context: &'static str,
        /// What happened
        // We the programmer know that this error type comes from the `certval` crate,
        // but that is not in scope at this point and doesn't implement `std::error::Error`,
        // so ¯\_(ツ)_/¯
        upstream: String,
    },
    /// Something in the MLS client went wrong
    #[error("{context}")]
    MlsClient {
        /// What was happening when the error was thrown
        context: &'static str,
        /// The inner error which was produced
        #[source]
        source: Box<crate::mls::client::error::Error>,
    },
    /// Something in the MLS credential went wrong
    #[error("{context}")]
    MlsCredential {
        /// What was happening when the error was thrown
        context: &'static str,
        /// The inner error which was produced
        #[source]
        source: Box<crate::mls::credential::error::Error>,
    },
    /// Something in the MLS conversation went wrong
    #[error("{context}")]
    Conversation {
        /// What was happening when the error was thrown
        context: &'static str,
        /// What happend within the conversation
        #[source]
        source: Box<crate::mls::conversation::error::Error>,
    },
    /// A MLS operation failed
    #[error("{context}")]
    MlsOperation {
        /// What the caller was doing at the time
        context: &'static str,
        /// What happened in MLS
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },
    /// A key store operation failed
    //
    // This uses a `Box<dyn>` pattern because we do not directly import `keystore` from here right now,
    // and it feels a bit silly to add the dependency only for this.
    #[error("{context}")]
    Keystore {
        /// What happened witht the keystore
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
        /// What was happening in the caller
        context: &'static str,
    },
    /// Something in the MLS root module went wrong
    #[error("{context}")]
    MlsRoot {
        /// What was happening in the caller
        context: &'static str,
        /// What happened
        #[source]
        source: Box<crate::mls::error::Error>,
    },
    /// Something in the root module went wrong
    #[error("{context}")]
    Root {
        /// What was happening in the caller
        context: &'static str,
        /// What happened
        #[source]
        source: Box<crate::Error>,
    },
}

impl Error {
    pub(crate) fn certificate_validation<E>(context: &'static str) -> impl FnOnce(E) -> Self
    where
        E: std::fmt::Debug,
    {
        move |source| Self::CertificateValidation {
            context,
            upstream: format!("{source:?}"),
        }
    }

    pub(crate) fn mls_client(context: &'static str) -> impl FnOnce(crate::mls::client::error::Error) -> Self {
        move |source| Self::MlsClient {
            context,
            source: Box::new(source),
        }
    }

    pub(crate) fn conversation(context: &'static str) -> impl FnOnce(crate::mls::conversation::error::Error) -> Self {
        move |source| Self::Conversation {
            context,
            source: Box::new(source),
        }
    }

    pub(crate) fn credential(context: &'static str) -> impl FnOnce(crate::mls::credential::error::Error) -> Self {
        move |source| Self::MlsCredential {
            context,
            source: Box::new(source),
        }
    }

    pub(crate) fn mls(context: &'static str) -> impl FnOnce(crate::mls::error::Error) -> Self {
        move |source| Self::MlsRoot {
            context,
            source: Box::new(source),
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

    pub(crate) fn keystore<E>(context: &'static str) -> impl FnOnce(E) -> Self
    where
        E: 'static + std::error::Error + Send + Sync,
    {
        move |err| Self::Keystore {
            context,
            source: Box::new(err),
        }
    }

    pub(crate) fn root(context: &'static str) -> impl FnOnce(crate::Error) -> Self {
        move |source| Self::Root {
            context,
            source: Box::new(source),
        }
    }
}
