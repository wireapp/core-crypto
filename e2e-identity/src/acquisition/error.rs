use rusty_jwt_tools::prelude::RustyJwtError;

use crate::pki_env::hooks::PkiEnvironmentHooksError;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("a PKI environment hook failed")]
    HookFailed(#[from] PkiEnvironmentHooksError),
    #[error("JSON parsing failed")]
    Json(#[from] serde_json::Error),
    #[error("HTTP response is missing header '{0}'")]
    MissingHeader(&'static str),
    #[error(transparent)]
    Acme(#[from] crate::acme::RustyAcmeError),
    #[error(transparent)]
    RustyJwtError(#[from] RustyJwtError),
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
