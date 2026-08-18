//! MLS credential errors

// We allow missing documentation in the error module because the types are generally self-descriptive.
#![allow(missing_docs)]

use openmls::prelude::SignaturePublicKey;

pub(crate) type Result<T, E = Error> = core::result::Result<T, E>;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("decoding X509 certificate")]
    DecodeX509(#[source] x509_cert::der::Error),
    #[error("client presented an invalid identity")]
    InvalidIdentity,
    #[error("No credential for the given public key ({0:?}) was found in this database")]
    CredentialNotFound(SignaturePublicKey),
    #[error("missing PKI environment")]
    MissingPKIEnvironment,
    /// Unsupported credential type.
    ///
    /// Supported credential types:
    ///
    /// - basic
    /// - x509
    #[error("unsupported credential type (variant {0}")]
    UnsupportedCredentialType(u16),
    #[error("the signature scheme {0:?} was not present in the provided x509 identity")]
    SignatureSchemeNotPresentInX509Identity(openmls::prelude::SignatureScheme),
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
    UnknownCipherSuite(#[from] crate::mls::UnknownCipherSuite),
    #[error(transparent)]
    Keystore(#[from] crate::KeystoreError),
    #[error(transparent)]
    OpenMls(#[from] crate::OpenMlsError),
    #[error(transparent)]
    Recursive(#[from] crate::RecursiveError),
    #[error(transparent)]
    Tls(#[from] crate::TlsCodecError),
}
