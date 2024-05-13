//! End to end identity errors

use crate::prelude::MlsCredentialType;
use core_crypto_keystore::CryptoKeystoreError;

/// Wrapper over a [Result] of an end to end identity error
pub type E2eIdentityResult<T> = Result<T, E2eIdentityError>;

/// End to end identity errors
#[derive(Debug, thiserror::Error)]
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
}
