//! MLS credential errors

// We allow missing documentation in the error module because the types are generally self-descriptive.
#![allow(missing_docs)]

pub(crate) type Result<T, E = Error> = core::result::Result<T, E>;

#[derive(Debug, thiserror::Error)]
pub enum Error {
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
    Keystore(#[from] crate::KeystoreError),
    #[error(transparent)]
    Mls(#[from] crate::MlsError),
    #[error(transparent)]
    Recursive(#[from] crate::RecursiveError),
    #[error("TLS serializing {item}")]
    TlsSerialize {
        #[source]
        source: tls_codec::Error,
        item: &'static str,
    },
    #[error("TLS deserializing {item}")]
    TlsDeserialize {
        #[source]
        source: tls_codec::Error,
        item: &'static str,
    },
}

impl Error {
    pub fn tls_serialize(item: &'static str) -> impl FnOnce(tls_codec::Error) -> Self {
        move |source| Self::TlsSerialize { source, item }
    }

    pub fn tls_deserialize(item: &'static str) -> impl FnOnce(tls_codec::Error) -> Self {
        move |source| Self::TlsDeserialize { source, item }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum CredentialValidationError {
    #[error("identity or public key did not match")]
    WrongCredential,
    #[error("public key not extractable from certificate")]
    NoPublicKey,
    #[error(transparent)]
    Recursive(#[from] crate::RecursiveError),
}
