//! End to end identity errors

use crate::prelude::MlsCredentialType;
use core_crypto_keystore::CryptoKeystoreError;

/// Wrapper over a [Result] of an end to end identity error
pub type E2eIdentityResult<T> = Result<T, E2eIdentityError>;

/// End to end identity errors
#[derive(Debug, thiserror::Error)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Error))]
#[cfg_attr(feature = "uniffi", uniffi(flat_error))]
pub enum E2eIdentityError {
    /// Client misused this library
    #[error("Incorrect usage of this API")]
    ImplementationError,
    /// Incoming support
    #[error("Not yet supported")]
    NotYetSupported,
    /// The required local MLS client was not initialized. It's likely a consumer error
    #[error("Expected a MLS client with credential type {0:?} but none found")]
    MissingExistingClient(MlsCredentialType),
    /// Cannot read the identity in the EE certificate
    #[error("Could not the identity information in the Credential's certificate")]
    InvalidIdentity,
    /// Failed converting the MLS signature key for the e2ei enrollment
    #[error("Failed converting the MLS signature key for the e2ei enrollment")]
    InvalidSignatureKey,
    /// Enrollment methods are called out of order
    #[error("Enrollment methods are called out of order: {0}")]
    OutOfOrderEnrollment(&'static str),
    /// Error when an end-to-end-identity domain is not well-formed utf-16, which means it's out of spec
    #[error("The E2EI provided domain is invalid utf-16")]
    E2eiInvalidDomain,
    /// Invalid OIDC RefreshToken supplied
    #[error("Invalid OIDC RefreshToken supplied")]
    InvalidRefreshToken,
    /// An error occurred while trying to persist the RefreshToken in the keystore
    #[error("An error occurred while trying to persist the RefreshToken in the keystore")]
    KeyStoreError(#[from] CryptoKeystoreError),
    /// Error generating keys
    #[error(transparent)]
    CryptoError(#[from] openmls_traits::types::CryptoError),
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
    /// Utf8 error
    #[error(transparent)]
    Utf8Error(#[from] ::core::str::Utf8Error),
    /// !!!! Something went very wrong and one of our locks has been poisoned by an in-thread panic !!!!
    #[error("One of the locks has been poisoned")]
    LockPoisonError,
}
