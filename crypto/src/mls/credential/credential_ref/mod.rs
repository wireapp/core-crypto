//! Definitions and implementations for [`CredentialRef`].

mod error;
mod find;
mod persistence;

use openmls::prelude::SignatureScheme;

pub(crate) use self::error::{Error, Result};
pub use self::find::{FindFilters, FindFiltersBuilder};
use crate::{Ciphersuite, ClientId, ClientIdRef, CredentialType};

/// A reference to a credential which has been stored in a session.
///
/// Credentials can be quite large; we'd really like to avoid passing them
/// back and forth across the FFI boundary more than is strictly required.
/// Therefore, we use this type which is substantially more compact.
///
/// Created with [`TransactionContext::add_credential`][crate::transaction_context::TransactionContext::add_credential].
///
/// This reference is _not_ a literal reference in memory.
/// It is instead a key with which a credential can be retrieved.
/// This means that it is stable over time and across the FFI boundary.
#[derive(
    core_crypto_macros::Debug, Clone, derive_more::From, derive_more::Into, serde::Serialize, serde::Deserialize,
)]
pub struct CredentialRef {
    client_id: ClientId,
    public_key: Vec<u8>,
    r#type: CredentialType,
    ciphersuite: Ciphersuite,
    // first unix timestamp at which the credential is valid
    earliest_validity: u64,
}

impl CredentialRef {
    /// Construct an instance from a credential.
    // not an actual `From` impl in order to keep it crate-private
    pub(crate) fn from_credential(credential: &super::Credential) -> Self {
        Self {
            client_id: credential.client_id().to_owned(),
            public_key: credential.signature_key_pair.public().to_owned(),
            r#type: credential.credential_type(),
            ciphersuite: credential.ciphersuite(),
            earliest_validity: credential.earliest_validity,
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
        self.ciphersuite.signature_algorithm()
    }

    /// Get the ciphersuite associated with this credential
    pub fn ciphersuite(&self) -> Ciphersuite {
        self.ciphersuite
    }

    /// Get the unix timestamp of the earliest validity of this credential.
    pub fn earliest_validity(&self) -> u64 {
        self.earliest_validity
    }
}
