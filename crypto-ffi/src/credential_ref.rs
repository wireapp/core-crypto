use core_crypto::CredentialRef as CryptoCredentialRef;

use crate::{Ciphersuite, ClientId, CredentialType, SignatureScheme};

/// A compact reference to a credential that has been persisted in CoreCrypto.
///
/// Credentials can be quite large; this type avoids passing them back and forth across the FFI
/// boundary more than strictly required.
///
/// Created by calling `add_credential` on a `CoreCryptoContext`.
///
/// This reference is not a literal in-memory reference.
/// It is instead the key from which a credential can be retrieved,
/// and is stable over time and across the FFI boundary.
#[derive(Debug, Clone, derive_more::From, derive_more::Into, uniffi::Object)]
#[uniffi::export(Debug)]
pub struct CredentialRef(pub(crate) CryptoCredentialRef);

#[uniffi::export]
impl CredentialRef {
    /// Get the client id associated with this credential ref.
    pub fn client_id(&self) -> ClientId {
        self.0.client_id().to_owned().into()
    }

    /// Get the SHA256 hash of the public key associated with this credential ref.
    pub fn public_key_hash(&self) -> Vec<u8> {
        self.0.public_key_hash().to_vec()
    }

    /// Get the type of this credential ref.
    pub fn r#type(&self) -> CredentialType {
        self.0.r#type().into()
    }

    /// Get the signature scheme of this credential ref.
    pub fn signature_scheme(&self) -> SignatureScheme {
        self.0.signature_scheme().into()
    }

    /// Get the ciphersuite of this credential ref.
    pub fn ciphersuite(&self) -> Ciphersuite {
        self.0.ciphersuite().into()
    }

    /// Get the earliest possible validity of this credential, expressed as seconds after the unix epoch.
    ///
    /// Basic credentials have no defined earliest validity and will always return 0.
    pub fn earliest_validity(&self) -> u64 {
        self.0.earliest_validity()
    }
}
