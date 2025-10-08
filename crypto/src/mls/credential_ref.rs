//! Definitions and implementations for [`CredentialRef`].

use openmls::prelude::{CredentialType, SignatureScheme};

use crate::{ClientId, ClientIdRef};

/// A reference to a credential.
///
/// Credentials can be quite large; we'd really like to avoid passing them
/// back and forth across the FFI boundary more than is strictly required.
/// Therefore, we invent this type which is substantially more compact.
///
/// This reference is _not_ a literal reference in memory.
/// It is instead the key from which a credential can be retrieved.
/// This means that it is stable over time and across the FFI boundary.
#[derive(core_crypto_macros::Debug, Clone, derive_more::Constructor, derive_more::From, derive_more::Into)]
pub struct CredentialRef {
    client_id: ClientId,
    r#type: CredentialType,
    signature_scheme: SignatureScheme,
}

impl CredentialRef {
    /// Get the client ID associated with this credential
    pub fn client_id(&self) -> &ClientIdRef {
        self.client_id.as_ref()
    }

    /// Get the credential type associated with this credential
    pub fn r#type(&self) -> CredentialType {
        self.r#type
    }

    /// Get the signature scheme associated with this credential
    pub fn signature_scheme(&self) -> SignatureScheme {
        self.signature_scheme
    }
}
