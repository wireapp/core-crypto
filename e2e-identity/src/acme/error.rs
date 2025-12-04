/// Wrapper over a [Result] with a [RustyAcmeError] error
pub type RustyAcmeResult<T> = Result<T, RustyAcmeError>;

/// All errors which [crate::RustyAcme] might throw
#[derive(Debug, thiserror::Error)]
pub enum RustyAcmeError {
    /// Invalid Json representation
    #[error(transparent)]
    JsonError(#[from] serde_json::Error),
    /// Invalid URL
    #[error(transparent)]
    UrlError(#[from] url::ParseError),
    /// Error while building a JWT
    #[error(transparent)]
    JwtError(#[from] rusty_jwt_tools::prelude::RustyJwtError),
    /// Error related to various X509 processing facilities/tools/checks
    #[error(transparent)]
    X509CheckError(#[from] crate::acme::x509_check::RustyX509CheckError),
    /// Failed mapping an ASN.1 ObjectIdentifier
    #[error(transparent)]
    OidError(#[from] x509_cert::der::oid::Error),
    /// Failed mapping a DER certificate
    #[error(transparent)]
    DerError(#[from] x509_cert::der::Error),
    /// Error while parsing a PEM document
    #[error(transparent)]
    PemError(#[from] pem::PemError),
    /// Error while handling a JWT
    #[error(transparent)]
    RawJwtError(#[from] jwt_simple::Error),
    /// Error with hand-rolled signature
    #[error(transparent)]
    SignatureError(#[from] signature::Error),
    /// We have done something terribly wrong
    #[error("We have done something terribly wrong and it needs to be fixed")]
    ImplementationError,
    /// Mostly related to WASM support
    #[error("Requested functionality is not supported for the moment")]
    NotSupported,
    /// This library has been used the wrong way by users
    #[error("This library has been used the wrong way by users because {0}")]
    ClientImplementationError(&'static str),
    /// Smallstep ACME server is not correctly implemented
    #[error("Incorrect response from ACME server because {0}")]
    SmallstepImplementationError(&'static str),
    /// Error while processing an account
    #[error(transparent)]
    AccountError(#[from] crate::acme::account::AcmeAccountError),
    /// Error while processing an order
    #[error(transparent)]
    OrderError(#[from] crate::acme::order::AcmeOrderError),
    /// Error while processing an authorization
    #[error(transparent)]
    AuthzError(#[from] crate::acme::authz::AcmeAuthzError),
    /// Error while validating a challenge
    #[error(transparent)]
    ChallengeError(#[from] crate::acme::chall::AcmeChallError),
    /// Error while finalizing an order
    #[error(transparent)]
    FinalizeError(#[from] crate::acme::finalize::AcmeFinalizeError),
    /// UTF-8 parsing error
    #[error(transparent)]
    Utf8(#[from] std::str::Utf8Error),
    /// Invalid/incomplete certificate
    #[error(transparent)]
    InvalidCertificate(#[from] CertificateError),
}

/// Given x509 certificate is invalid and does not follow Wire's format
#[derive(Debug, thiserror::Error)]
pub enum CertificateError {
    /// ClientId does not match expected one
    #[error("ClientId does not match expected one")]
    ClientIdMismatch,
    /// Display name does not match expected one
    #[error("Display name does not match expected one")]
    DisplayNameMismatch,
    /// Handle does not match expected one
    #[error("Handle does not match expected one")]
    HandleMismatch,
    /// Domain does not match expected one
    #[error("Domain does not match expected one")]
    DomainMismatch,
    /// DisplayName is missing from the certificate
    #[error("DisplayName is missing from the certificate")]
    MissingDisplayName,
    /// Handle is missing from the certificate
    #[error("Handle is missing from the certificate")]
    MissingHandle,
    /// Domain is missing from the certificate
    #[error("Domain is missing from the certificate")]
    MissingDomain,
    /// ClientId is missing from the certificate
    #[error("ClientId is missing from the certificate")]
    MissingClientId,
    /// X509 lacks required standard fields
    #[error("X509 lacks required standard fields")]
    InvalidFormat,
    /// Advertised public key does not match algorithm
    #[error("Advertised public key does not match algorithm")]
    InvalidPublicKey,
    /// Advertised public key is not supported
    #[error("Advertised public key is not supported")]
    UnsupportedPublicKey,
}
