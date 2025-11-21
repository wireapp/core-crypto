use std::sync::Arc;

use core_crypto::CredentialRef as CryptoCredentialRef;

use crate::{Ciphersuite, ClientId, CoreCryptoResult, CredentialType, SignatureScheme};

/// A reference to a credential which has been persisted in CC.
///
/// This is because credentials can be quite large; we'd really like to avoid passing them
/// back and forth across the FFI boundary more than is strictly required.
/// Therefore, we use this type which is substantially more compact.
///
/// Created with [`CoreCryptoContext::add_credential`][crate::CoreCryptoContext::add_credential].
///
/// This reference is _not_ a literal reference in memory.
/// It is instead the key from which a credential can be retrieved.
/// This means that it is stable over time and across the FFI boundary.
#[derive(Debug, Clone, derive_more::From, derive_more::Into, uniffi::Object)]
#[uniffi::export(Debug)]
pub struct CredentialRef(pub(crate) CryptoCredentialRef);

pub(crate) type CredentialRefMaybeArc = Arc<CredentialRef>;

impl CredentialRef {
    #[inline]
    pub(crate) fn into_maybe_arc(self) -> CredentialRefMaybeArc {
        Arc::new(self)
    }
}

#[uniffi::export]
impl CredentialRef {
    /// Get the client id associated with this credential ref
    pub fn client_id(&self) -> ClientId {
        self.0.client_id().to_owned().into()
    }

    /// Get the public key associated with this credential ref
    pub fn public_key(&self) -> Vec<u8> {
        self.0.public_key().to_owned()
    }

    /// Get the type of this credential ref.
    pub fn r#type(&self) -> CoreCryptoResult<CredentialType> {
        self.0.r#type().try_into()
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
