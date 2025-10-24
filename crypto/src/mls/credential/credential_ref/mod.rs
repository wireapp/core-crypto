//! Definitions and implementations for [`CredentialRef`].

mod error;
mod find;
mod persistence;

use openmls::prelude::{CredentialType, SignatureScheme};

pub(crate) use self::error::Result;
pub use self::{
    error::Error,
    find::{FindFilters, FindFiltersBuilder},
};
use crate::{ClientId, ClientIdRef};

/// A reference to a credential which has been stored in the database.
///
/// This serves two purposes:
///
/// 1. Credentials can be quite large; we'd really like to avoid passing them
///    back and forth across the FFI boundary more than is strictly required.
///    Therefore, we use this type which is substantially more compact.
/// 2. It serves as proof of persistence. If you have a `CredentialRef`, you know
///    that the credential it refers to has been saved in the database.
///    This gives us a typesafe way to require that credentials are saved before
///    they are added to a [`Session`][crate::Session].
///
/// Created with [`Credential::save`][crate::Credential::save].
///
/// This reference is _not_ a literal reference in memory.
/// It is instead the key from which a credential can be retrieved.
/// This means that it is stable over time and across the FFI boundary.
#[derive(
    core_crypto_macros::Debug, Clone, derive_more::From, derive_more::Into, serde::Serialize, serde::Deserialize,
)]
pub struct CredentialRef {
    client_id: ClientId,
    public_key: Vec<u8>,
    r#type: CredentialType,
    signature_scheme: SignatureScheme,
    // first unix timestamp at which the credential is valid
    earliest_validity: u64,
}

impl CredentialRef {
    /// Construct an instance from its parts.
    ///
    /// This _must_ remain crate-private at most so that we can use this type
    /// as proof of persistence! Use caution when calling this method to retain this property.
    pub(super) const fn new(
        client_id: ClientId,
        public_key: Vec<u8>,
        r#type: CredentialType,
        signature_scheme: SignatureScheme,
        earliest_validity: u64,
    ) -> Self {
        Self {
            client_id,
            public_key,
            r#type,
            signature_scheme,
            earliest_validity,
        }
    }

    /// Get the client ID associated with this credential
    pub fn client_id(&self) -> &ClientIdRef {
        self.client_id.as_ref()
    }

    /// Get the public key associated with this credential
    pub fn public_key(&self) -> &[u8] {
        &self.public_key
    }

    /// Get the credential type associated with this credential
    pub fn r#type(&self) -> CredentialType {
        self.r#type
    }

    /// Get the signature scheme associated with this credential
    pub fn signature_scheme(&self) -> SignatureScheme {
        self.signature_scheme
    }

    /// Get the unix timestamp of the earliest validity of this credential.
    pub fn earliest_validity(&self) -> u64 {
        self.earliest_validity
    }
}
