//! MLS credential errors

// We allow missing documentation in the error module because the types are generally self-descriptive.
#![allow(missing_docs)]

pub type Result<T, E = Error> = core::result::Result<T, E>;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("The certificate chain is invalid or not complete")]
    InvalidCertificateChain,
    #[error("decoding X509 certificate")]
    DecodeX509(#[source] x509_cert::der::Error),
    #[error("Client presented an invalid identity")]
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
    // This uses a `Box<dyn>` pattern because we do not directly import `keystore` from here right now,
    // and it feels a bit silly to add the dependency only for this.
    #[error("{context}")]
    Keystore {
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
        context: &'static str,
    },
    #[error("{context}")]
    MlsOperation {
        context: &'static str,
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },
    #[error(transparent)]
    Recursive(#[from] crate::RecursiveError),
}

impl Error {
    pub(crate) fn keystore<E>(context: &'static str) -> impl FnOnce(E) -> Self
    where
        E: 'static + std::error::Error + Send + Sync,
    {
        move |err| Self::Keystore {
            context,
            source: Box::new(err),
        }
    }

    pub(crate) fn mls_operation<E>(context: &'static str) -> impl FnOnce(E) -> Self
    where
        E: 'static + std::error::Error + Send + Sync,
    {
        move |source| Self::MlsOperation {
            context,
            source: Box::new(source),
        }
    }
}
