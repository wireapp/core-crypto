use std::sync::Arc;

use core_crypto::{CipherSuite as CryptoCiphersuite, Credential as CryptoCredential};

use crate::{Ciphersuite, CoreCryptoResult, CredentialType, SignatureScheme, client_id::ClientId};

/// A cryptographic credential.
///
/// This is tied to a particular client via either its client id or certificate bundle,
/// depending on its credential type, but is independent of any client instance or storage.
///
/// To attach a credential to a client instance and store it, call `add_credential` on a `CoreCryptoContext`.
#[derive(Debug, Clone, derive_more::From, derive_more::Into, uniffi::Object)]
pub struct Credential(pub(crate) CryptoCredential);

#[uniffi::export]
impl Credential {
    /// Generate a basic credential.
    ///
    /// The result is independent of any client instance and the database; it lives in memory only.
    #[uniffi::constructor(name = "basic")]
    fn basic(ciphersuite: Ciphersuite, client_id: &Arc<ClientId>) -> CoreCryptoResult<Self> {
        let client_id_ref = client_id.as_ref().as_ref();
        CryptoCredential::basic(CryptoCiphersuite::from(ciphersuite), client_id_ref.to_owned())
            .map(Into::into)
            .map_err(Into::into)
    }

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
