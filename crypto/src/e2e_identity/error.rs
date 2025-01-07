//! End to end identity errors

// We allow missing documentation in the error module because the types are generally self-descriptive.
#![allow(missing_docs)]

use crate::prelude::MlsCredentialType;
use core_crypto_keystore::CryptoKeystoreError;

pub type Result<T, E = Error> = core::result::Result<T, E>;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Incorrect usage of this API")]
    ImplementationError,
    #[error("Not yet supported")]
    NotYetSupported,
    #[error("Expected a MLS client with credential type {0:?} but none found")]
    MissingExistingClient(MlsCredentialType),
    #[error("Enrollment methods are called out of order: {0}")]
    OutOfOrderEnrollment(&'static str),
    #[error("Invalid OIDC RefreshToken supplied")]
    InvalidRefreshToken,
    #[error("We already have an ACME Root Trust Anchor registered. Cannot proceed but this is usually indicative of double registration and can be ignored")]
    TrustAnchorAlreadyRegistered,
    #[error("The encountered ClientId does not match Wire's definition")]
    InvalidClientId,
    #[error("This function accepts a list of IDs as a parameter, but that list was empty")]
    EmptyInputIdList,
    #[error("PKI Environment must be set before calling this function")]
    PkiEnvironmentUnset,
    #[error("An error occurred while trying to persist the RefreshToken in the keystore")]
    KeyStoreError(#[from] CryptoKeystoreError),
    #[error(transparent)]
    IdentityError(#[from] wire_e2e_identity::prelude::E2eIdentityError),
    #[error(transparent)]
    X509Error(#[from] wire_e2e_identity::prelude::x509::RustyX509CheckError),
    #[error(transparent)]
    UrlError(#[from] url::ParseError),
    #[error(transparent)]
    JsonError(#[from] serde_json::Error),
    #[error(transparent)]
    X509CertDerError(#[from] x509_cert::der::Error),
    #[error("Serializing key package for TLS")]
    TlsSerializingKeyPackage(#[from] tls_codec::Error),
    #[error("{context}: {upstream}")]
    CertificateValidation {
        context: &'static str,
        // We the programmer know that this error type comes from the `certval` crate,
        // but that is not in scope at this point and doesn't implement `std::error::Error`,
        // so ¯\_(ツ)_/¯
        upstream: String,
    },
    #[error(transparent)]
    Mls(#[from] crate::MlsError),
    #[error(transparent)]
    Keystore(#[from] crate::KeystoreError),
    #[error("{0}")]
    Leaf(#[from] crate::LeafError),
    #[error(transparent)]
    Recursive(#[from] crate::RecursiveError),
}

impl Error {
    pub(crate) fn certificate_validation<E>(context: &'static str) -> impl FnOnce(E) -> Self
    where
        E: std::fmt::Debug,
    {
        move |source| Self::CertificateValidation {
            context,
            upstream: format!("{source:?}"),
        }
    }
}
