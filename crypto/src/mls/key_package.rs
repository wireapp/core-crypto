//! MLS Keypackage helpers.
//!
//! Turns out that Openmls already defines both `KeyPackage` and `KeyPackageRef`, so there's not a ton of point
//! redefining either of those structs here. That would just lead to a bunch of redefinition.
//!
//! On the other hand, the `KeyPackage` API isn't strictly ideal, so we improve on it here.

use std::sync::LazyLock;

use mls_crypto_provider::RustCrypto;
use openmls::prelude::{KeyPackage, KeyPackageRef};

use crate::{Ciphersuite, CredentialType, MlsError};

static CRYPTO: LazyLock<RustCrypto> = LazyLock::new(RustCrypto::default);

/// Extensions on the `KeyPackage` type for nicer usage patterns.
pub trait KeyPackageExt {
    /// Delegates to [`KeyPackage::hash_ref`] with a static crypto instance.
    fn make_ref(&self) -> Result<KeyPackageRef, MlsError>;

    /// Returns the ciphersuite associated this this key package.
    fn ciphersuite(&self) -> Ciphersuite;

    /// Returns the credential type associated with this key package.
    fn credential_type(&self) -> CredentialType;

    /// Determines whether a keypackage is valid in the sense of the former `client_valid_keypackages_count` method.
    ///
    /// In practice, this just checks whether its lifetime (if present) has expired or not.
    fn is_valid(&self) -> bool;
}

impl KeyPackageExt for KeyPackage {
    fn make_ref(&self) -> Result<KeyPackageRef, MlsError> {
        self.hash_ref(&*CRYPTO)
            .map_err(MlsError::wrap("computing keypackage hash ref"))
    }

    fn ciphersuite(&self) -> Ciphersuite {
        <KeyPackage>::ciphersuite(&self).into()
    }

    fn credential_type(&self) -> CredentialType {
        self.leaf_node()
            .credential()
            .credential_type()
            .try_into()
            .expect("we should only ever have a key package from a credential that this instance of CC understands")
    }

    fn is_valid(&self) -> bool {
        self.leaf_node()
            .life_time()
            .is_none_or(|lifetime| lifetime.has_acceptable_range() && lifetime.is_valid())
    }
}
