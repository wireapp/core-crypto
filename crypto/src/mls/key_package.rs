//! MLS Keypackage helpers.
//!
//! Turns out that Openmls already defines both `KeyPackage` and `KeyPackageRef`, so there's not a ton of point
//! redefining either of those structs here. That would just lead to a bunch of redefinition.
//!
//! On the other hand, the `KeyPackage` API isn't strictly ideal, so we improve on it here.

pub use openmls::prelude::KeyPackage as Keypackage;
use openmls::prelude::{KeyPackageRef as KpHashRef, Lifetime, SignatureScheme};

use crate::{CipherSuite, CredentialType, OpenMlsError, mls_provider::CRYPTO};

/// Extensions on the `KeyPackage` type for nicer usage patterns.
pub trait KeypackageExt {
    /// Make a "fat" [`KeypackageRef`] from this [`Keypackage`].
    ///
    /// This is a fairly inexpensive operation.
    fn make_ref(&self) -> Result<KeypackageRef, OpenMlsError>;

    /// Returns the ciphersuite associated this this key package.
    fn cipher_suite(&self) -> CipherSuite;

    /// Returns the credential type associated with this key package.
    fn credential_type(&self) -> CredentialType;

    /// Determines whether a keypackage is valid in the sense of the former `client_valid_keypackages_count` method.
    ///
    /// In practice, this just checks whether its lifetime (if present) has expired or not.
    fn is_valid(&self) -> bool;
}

impl KeypackageExt for Keypackage {
    fn make_ref(&self) -> Result<KeypackageRef, OpenMlsError> {
        let hash_ref = self
            .hash_ref(CRYPTO.as_ref())
            .map_err(OpenMlsError::wrap("computing keypackage hash ref"))?;

        let cipher_suite = <Self as KeypackageExt>::cipher_suite(self);
        let credential_type = self.credential_type();
        let lifetime = self.leaf_node().life_time().cloned();

        Ok(KeypackageRef {
            hash_ref,
            cipher_suite,
            credential_type,
            lifetime,
        })
    }

    fn cipher_suite(&self) -> CipherSuite {
        <Keypackage>::ciphersuite(self).into()
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

/// A "fat" reference to a [`Keypackage`].
///
/// Contains the relevant hash, and also information about its cipher suite, credential type, and lifetime.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeypackageRef {
    hash_ref: KpHashRef,
    cipher_suite: CipherSuite,
    credential_type: CredentialType,
    lifetime: Option<Lifetime>,
}

impl KeypackageRef {
    /// Get the bytes of the hash reference to a [`Keypackage`]
    pub fn hash_ref(&self) -> &[u8] {
        self.hash_ref.as_slice()
    }

    /// Get the cipher suite associated with this key package ref.
    pub fn cipher_suite(&self) -> CipherSuite {
        self.cipher_suite
    }

    /// Get the signature scheme associated wtih this key package ref.
    pub fn signature_scheme(&self) -> SignatureScheme {
        self.cipher_suite.signature_algorithm()
    }

    /// Get the credential type associated with this key package ref.
    pub fn credential_type(&self) -> CredentialType {
        self.credential_type
    }

    /// Get the lifetime associated with this key package ref.
    pub fn lifetime(&self) -> Option<&Lifetime> {
        self.lifetime.as_ref()
    }

    /// Determines whether this keypackage is valid in the sense of the former `client_valid_keypackages_count` method.
    ///
    /// In practice, this just checks whether its lifetime (if present) has expired or not.
    pub fn is_valid(&self) -> bool {
        self.lifetime()
            .is_none_or(|lifetime| lifetime.has_acceptable_range() && lifetime.is_valid())
    }
}

impl KeypackageExt for KeypackageRef {
    fn make_ref(&self) -> Result<KeypackageRef, OpenMlsError> {
        Ok(self.clone())
    }

    fn cipher_suite(&self) -> CipherSuite {
        self.cipher_suite
    }

    fn credential_type(&self) -> CredentialType {
        self.credential_type
    }

    fn is_valid(&self) -> bool {
        <Self>::is_valid(self)
    }
}
