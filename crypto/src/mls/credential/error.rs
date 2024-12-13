//! MLS credential errors

// We allow missing documentation in the error module because the types are generally self-descriptive.
#![allow(missing_docs)]

pub(crate) type Result<T, E = Error> = core::result::Result<T, E>;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("The certificate chain is invalid or not complete")]
    InvalidCertificateChain,
    #[error("decoding X509 certificate")]
    DecodeX509(#[source] x509_cert::der::Error),
    #[error("client presented an invalid identity")]
    InvalidIdentity,
    /// Unsupported credential type.
    ///
    /// Supported credential types:
    ///
    /// - basic
    /// - x509
    #[error("unsupported credential type")]
    UnsupportedCredentialType,
    /// This operation is not supported.
    ///
    /// There are some operations which must be implemented to satisfy a trait,
    /// but for which we cannot offer a real implementation. Those raise this error.
    ///
    /// Where possible, a short workaround is included.
    #[error("unsupported operation. prefer `{0}`")]
    UnsupportedOperation(&'static str),
    #[error("unsupported algorithm")]
    UnsupportedAlgorithm,
    #[error(transparent)]
    Keystore(#[from] crate::KeystoreError),
    #[error(transparent)]
    Mls(#[from] crate::MlsError),
    #[error(transparent)]
    Recursive(#[from] crate::RecursiveError),
}
