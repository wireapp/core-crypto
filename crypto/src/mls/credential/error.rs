//! MLS credential errors

/// Module-specific wrapper aroud a [Result][core::result::Result].
pub type Result<T, E = Error> = core::result::Result<T, E>;

/// MLS credential errors
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The certificate chain is invalid or not complete
    #[error("The certificate chain is invalid or not complete")]
    InvalidCertificateChain,
    #[error("decoding X509 certificate")]
    DecodeX509(#[source] x509_cert::der::Error),
    /// Client presented an invalid identity
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
    /// Unsupported algorithm
    #[error("unsupported algorithm")]
    UnsupportedAlgorithm,
    /// Something went wrong in e2e identity
    #[error("{context}")]
    E2e {
        /// What was happening in the caller at the time
        context: &'static str,
        /// What happened in e2e
        #[source]
        source: Box<crate::e2e_identity::error::Error>,
    },
    /// A key store operation failed
    //
    // This uses a `Box<dyn>` pattern because we do not directly import `keystore` from here right now,
    // and it feels a bit silly to add the dependency only for this.
    #[error("{context}")]
    Keystore {
        /// What happened in the keystore
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
        /// What the caller was doing at the time
        context: &'static str,
    },
    /// A MLS operation failed
    #[error("{context}")]
    MlsOperation {
        /// What the caller was doing at the time
        context: &'static str,
        /// What happened in MLS
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },
    /// Compatibility wrapper
    ///
    /// This should be removed before merging this branch, but it allows an easier migration path to module-specific errors.
    #[deprecated]
    #[error(transparent)]
    CryptoError(Box<crate::CryptoError>),
}

impl From<crate::CryptoError> for Error {
    fn from(value: crate::CryptoError) -> Self {
        Self::CryptoError(Box::new(value))
    }
}

impl Error {
    pub(crate) fn e2e<E>(context: &'static str) -> impl FnOnce(E) -> Self
    where
        E: Into<crate::e2e_identity::error::Error>,
    {
        move |err| Self::E2e {
            context,
            source: Box::new(err.into()),
        }
    }

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
