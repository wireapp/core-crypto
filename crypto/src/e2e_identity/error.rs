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
}
