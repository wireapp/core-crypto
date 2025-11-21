use std::sync::Arc;

use core_crypto::{Ciphersuite as CryptoCiphersuite, Credential as CryptoCredential};
use mls_crypto_provider::RustCrypto;

use crate::{Ciphersuite, CoreCryptoResult, CredentialType, SignatureScheme, client_id::ClientIdMaybeArc};

/// A cryptographic credential.
///
/// This is tied to a particular client via either its client id or certificate bundle,
/// depending on its credential type, but is independent of any client instance or storage.
///
/// To attach to a particular client instance and store, see [`CoreCryptoContext::add_credential`][crate::CoreCryptoContext::add_credential].
#[derive(Debug, Clone, derive_more::From, derive_more::Into, uniffi::Object)]
pub struct Credential(pub(crate) CryptoCredential);

pub(crate) type CredentialMaybeArc = Arc<Credential>;

impl Credential {
    fn basic_impl(ciphersuite: Ciphersuite, client_id: &ClientIdMaybeArc) -> CoreCryptoResult<Self> {
        let crypto = RustCrypto::default();
        CryptoCredential::basic(CryptoCiphersuite::from(ciphersuite), client_id.as_cc(), crypto)
            .map(Into::into)
            .map_err(Into::into)
    }
}

/// Generate a basic credential.
///
/// The result is independent of any client instance and the database; it lives in memory only.
#[uniffi::export]
pub fn credential_basic(ciphersuite: Ciphersuite, client_id: &ClientIdMaybeArc) -> CoreCryptoResult<Credential> {
    Credential::basic_impl(ciphersuite, client_id)
}

#[uniffi::export]
impl Credential {
    /// Get the type of this credential.
    pub fn r#type(&self) -> CredentialType {
        self.0.credential_type().into()
    }

    /// Get the signature scheme of this credential.
    pub fn signature_scheme(&self) -> SignatureScheme {
        self.0.signature_scheme().into()
    }

    /// Get the earliest possible validity of this credential, expressed as seconds after the unix epoch.
    ///
    /// Basic credentials have no defined earliest validity and will always return 0.
    pub fn earliest_validity(&self) -> u64 {
        self.0.earliest_validity()
    }
}
