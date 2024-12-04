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
    #[error("We already have an ACME Root Trust Anchor registered. Cannot proceed but this is usually indicative of double registration and can be ignored")]
    TrustAnchorAlreadyRegistered,
    #[error("Getting MLS ratchet tree")]
    MlsRatchetTree(#[from] openmls::messages::group_info::GroupInfoError),
    #[error("Generating signature key")]
    SignatureKeyGen(#[source] openmls_traits::types::CryptoError),
    #[error("Normalizing ed25519 key")]
    NormalizingEd25519Key(#[source] openmls_traits::types::CryptoError),
    #[error("Generating new PKI keypair")]
    GeneratePkiKeypair(#[from] mls_crypto_provider::MlsProviderError),
    #[error("The encountered ClientId does not match Wire's definition")]
    InvalidClientId,
    #[error(transparent)]
    X509CertDerError(#[from] x509_cert::der::Error),
    #[error("This function accepts a list of IDs as a parameter, but that list was empty")]
    EmptyInputIdList,
    #[error("Getting user identities")]
    GetUserIdentities(#[source] crate::mls::client::Error),
    #[error("PKI Environment must be set before calling this function")]
    PkiEnvironmentUnset,
    #[error("Computing key package hash ref")]
    KeyPackageHashRef(#[from] openmls::error::LibraryError),
    #[error("Serializing key package for TLS")]
    TlsSerializingKeyPackage(#[from] tls_codec::Error),
    #[error("The MLS group is in an invalid state for an unknown reason")]
    InternalMlsError,
    #[error("{context}: {upstream}")]
    CertificateValidation {
        context: &'static str,
        // We the programmer know that this error type comes from the `certval` crate,
        // but that is not in scope at this point and doesn't implement `std::error::Error`,
        // so ¯\_(ツ)_/¯
        upstream: String,
    },
    #[error("{context}")]
    MlsClient {
        context: &'static str,
        #[source]
        source: Box<crate::mls::client::Error>,
    },
    #[error("{context}")]
    MlsCredential {
        context: &'static str,
        #[source]
        source: Box<crate::mls::credential::Error>,
    },
    #[error("{context}")]
    Conversation {
        context: &'static str,
        #[source]
        source: Box<crate::mls::conversation::Error>,
    },
    #[error("{context}")]
    MlsOperation {
        context: &'static str,
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },
    // This uses a `Box<dyn>` pattern because we do not directly import `keystore` from here right now,
    // and it feels a bit silly to add the dependency only for this.
    #[error("{context}")]
    Keystore {
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
        context: &'static str,
    },
    #[error("{context}")]
    MlsRoot {
        context: &'static str,
        #[source]
        source: Box<crate::mls::Error>,
    },
    #[error("{context}")]
    Root {
        context: &'static str,
        #[source]
        source: Box<crate::Error>,
    },
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

    pub(crate) fn mls_client(context: &'static str) -> impl FnOnce(crate::mls::client::Error) -> Self {
        move |source| Self::MlsClient {
            context,
            source: Box::new(source),
        }
    }

    pub(crate) fn conversation(context: &'static str) -> impl FnOnce(crate::mls::conversation::Error) -> Self {
        move |source| Self::Conversation {
            context,
            source: Box::new(source),
        }
    }

    pub(crate) fn credential(context: &'static str) -> impl FnOnce(crate::mls::credential::Error) -> Self {
        move |source| Self::MlsCredential {
            context,
            source: Box::new(source),
        }
    }

    pub(crate) fn mls(context: &'static str) -> impl FnOnce(crate::mls::Error) -> Self {
        move |source| Self::MlsRoot {
            context,
            source: Box::new(source),
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

    pub(crate) fn keystore<E>(context: &'static str) -> impl FnOnce(E) -> Self
    where
        E: 'static + std::error::Error + Send + Sync,
    {
        move |err| Self::Keystore {
            context,
            source: Box::new(err),
        }
    }

    pub(crate) fn root(context: &'static str) -> impl FnOnce(crate::Error) -> Self {
        move |source| Self::Root {
            context,
            source: Box::new(source),
        }
    }
}
