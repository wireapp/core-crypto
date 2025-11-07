//! MLS Keypackage helpers.
//!
//! Turns out that Openmls already defines both `KeyPackage` and `KeyPackageRef`, so there's not a ton of point
//! redefining either of those structs here. That would just lead to a bunch of redefinition.
//!
//! On the other hand, the `KeyPackage` API isn't strictly ideal, so we improve on it here.

use std::sync::LazyLock;

use mls_crypto_provider::RustCrypto;
use openmls::prelude::{KeyPackage, KeyPackageRef};

use crate::MlsError;

static CRYPTO: LazyLock<RustCrypto> = LazyLock::new(RustCrypto::default);

/// Extensions on the `KeyPackage` type for nicer usage patterns.
pub trait KeyPackageExt {
    /// Delegates to [`KeyPackage::hash_ref`] with a static crypto instance.
    fn make_ref(&self) -> Result<KeyPackageRef, MlsError>;
}

impl KeyPackageExt for KeyPackage {
    fn make_ref(&self) -> Result<KeyPackageRef, MlsError> {
        self.hash_ref(&*CRYPTO)
            .map_err(MlsError::wrap("computing keypackage hash ref"))
    }
}
