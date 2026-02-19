// We allow missing documentation in the error module because the types are generally
// self-descriptive.
#![allow(missing_docs)]

pub type E2eIdentityResult<T> = Result<T, E2eIdentityError>;

/// All e2e identity related errors
#[derive(Debug, thiserror::Error)]
pub enum E2eIdentityError {
    /// Invalid/incomplete certificate
    #[error("Given x509 certificate is invalid and does not follow Wire's format")]
    InvalidCertificate,
    /// Json error
    #[error(transparent)]
    JsonError(#[from] serde_json::Error),
    /// Acme error
    #[error(transparent)]
    AcmeError(#[from] crate::acme::RustyAcmeError),
    /// Error creating the client Dpop token
    #[error(transparent)]
    JwtError(#[from] rusty_jwt_tools::prelude::RustyJwtError),
    /// Core JWT error
    #[error(transparent)]
    JwtSimpleError(#[from] jwt_simple::Error),
    /// Not supported
    #[error("Not supported")]
    NotSupported,
    #[error("Incorrect usage of this API")]
    ImplementationError,
    #[error("Not yet supported")]
    NotYetSupported,
    #[error("Enrollment methods are called out of order: {0}")]
    OutOfOrderEnrollment(&'static str),
    #[error("Invalid OIDC RefreshToken supplied")]
    InvalidRefreshToken,
    #[error("The encountered ClientId does not match Wire's definition")]
    InvalidClientId,
    #[error("This function accepts a list of IDs as a parameter, but that list was empty")]
    EmptyInputIdList,
    #[error("No enrollment was found")]
    NotFound,
    #[error(transparent)]
    CryptoError(#[from] openmls_traits::types::CryptoError),
    #[error(transparent)]
    X509Error(#[from] crate::x509_check::RustyX509CheckError),
    #[error(transparent)]
    UrlError(#[from] url::ParseError),
    #[error(transparent)]
    X509CertDerError(#[from] x509_cert::der::Error),
    #[error("An error occured while generating an X509 certificate")]
    CertificateGenerationError,
    #[error("Unsupported signature scheme")]
    UnsupportedSignatureScheme,
    #[error("Signature key generation failed")]
    SignatureKeyGenerationFailed,
    #[error("Signing failed")]
    SigningFailed(#[from] signature::Error),
    #[error("{context}: {upstream}")]
    CertificateValidation {
        context: &'static str,
        // We the programmer know that this error type comes from the `certval` crate,
        // but that is not in scope at this point and doesn't implement `std::error::Error`,
        // so ¯\_(ツ)_/¯
        upstream: String,
    },
    #[error(transparent)]
    Keystore(#[from] core_crypto_keystore::CryptoKeystoreError),
}
