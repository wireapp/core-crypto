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
    #[error("Expected a MLS client with credential type {0:?} but none found")]
    MissingExistingClient(MlsCredentialType),
    #[error(
        "We already have an ACME Root Trust Anchor registered. Cannot proceed but this is usually indicative of double registration and can be ignored"
    )]
    TrustAnchorAlreadyRegistered,
    #[error("PKI Environment must be set before calling this function")]
    PkiEnvironmentUnset,
    #[error(transparent)]
    KeyStoreError(#[from] CryptoKeystoreError),
    #[error(transparent)]
    X509Error(#[from] wire_e2e_identity::prelude::x509::RustyX509CheckError),
    #[error(transparent)]
    X509CertDerError(#[from] x509_cert::der::Error),
    #[error(transparent)]
    Mls(#[from] crate::MlsError),
    #[error(transparent)]
    Keystore(#[from] crate::KeystoreError),
    #[error(transparent)]
    Recursive(#[from] crate::RecursiveError),
}
