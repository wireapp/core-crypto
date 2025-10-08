//! Definitions and implementations for [`CredentialRef`].

use crate::ClientId;

/// A reference to a credential.
///
/// Credentials can be quite large; we'd really like to avoid passing them
/// back and forth across the FFI boundary more than is strictly required.
/// Therefore, we invent this type which is substantially more compact.
///
/// This reference is _not_ a literal reference in memory.
/// It is instead the key from which a credential can be retrieved.
/// This means that it is stable over time and across the FFI boundary.
#[derive(core_crypto_macros::Debug, Clone, derive_more::From, derive_more::Into)]
pub struct CredentialRef(ClientId);
