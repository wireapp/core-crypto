//! End to end identity errors

/// Wrapper over a [Result] of an end to end identity error
pub type E2eIdentityResult<T> = Result<T, E2eIdentityError>;

/// End to end identity errors
#[derive(Debug, thiserror::Error)]
pub enum E2eIdentityError {
    /// Incoming support
    #[error("Not yet supported")]
    NotYetSupported,
    /// Error when an end-to-end-identity domain is not well-formed utf-16, which means it's out of spec
    #[error("The E2EI provided domain is invalid utf-16")]
    E2eiInvalidDomain,
    /// Error generating keys
    #[error(transparent)]
    CryptoError(#[from] openmls_traits::types::CryptoError),
    /// Error creating client Dpop token or acne error
    #[error(transparent)]
    IdentityError(#[from] wire_e2e_identity::prelude::E2eIdentityError),
    /// Error parsing a URL
    #[error(transparent)]
    UrlError(#[from] url::ParseError),
    /// Json error
    #[error(transparent)]
    JsonError(#[from] serde_json::Error),
    /// Utf8 error
    #[error(transparent)]
    Utf8Error(#[from] ::core::str::Utf8Error),
}
