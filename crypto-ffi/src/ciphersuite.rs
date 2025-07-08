//! Ciphersuites in bindings
//!
//! Both wasm-bindgen and uniffi support emitting enums, as long as they directly implement the enum;
//! it doesn't work on newtypes around external enums. We therefore redefine the ciphersuites enum
//! here with appropriate annotations such that it gets exported to all relevant bindings.

use core_crypto::prelude::{CiphersuiteName, MlsCiphersuite};
#[cfg(target_family = "wasm")]
use wasm_bindgen::prelude::*;

use crate::{CoreCryptoError, CoreCryptoResult};

/// MLS ciphersuites.
#[allow(non_camel_case_types)]
#[allow(clippy::upper_case_acronyms)]
#[derive(Default, Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, derive_more::TryFrom)]
#[try_from(repr)]
#[repr(u16)]
#[cfg_attr(target_family = "wasm", wasm_bindgen, derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(not(target_family = "wasm"), derive(uniffi::Enum))]
pub enum Ciphersuite {
    /// DH KEM x25519 | AES-GCM 128 | SHA2-256 | Ed25519
    #[default]
    MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519 = 0x0001,

    /// DH KEM P256 | AES-GCM 128 | SHA2-256 | EcDSA P256
    MLS_128_DHKEMP256_AES128GCM_SHA256_P256 = 0x0002,

    /// DH KEM x25519 | Chacha20Poly1305 | SHA2-256 | Ed25519
    MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519 = 0x0003,

    /// DH KEM x448 | AES-GCM 256 | SHA2-512 | Ed448
    MLS_256_DHKEMX448_AES256GCM_SHA512_Ed448 = 0x0004,

    /// DH KEM P521 | AES-GCM 256 | SHA2-512 | EcDSA P521
    MLS_256_DHKEMP521_AES256GCM_SHA512_P521 = 0x0005,

    /// DH KEM x448 | Chacha20Poly1305 | SHA2-512 | Ed448
    MLS_256_DHKEMX448_CHACHA20POLY1305_SHA512_Ed448 = 0x0006,

    /// DH KEM P384 | AES-GCM 256 | SHA2-384 | EcDSA P384
    MLS_256_DHKEMP384_AES256GCM_SHA384_P384 = 0x0007,
}

impl From<Ciphersuite> for CiphersuiteName {
    #[inline]
    fn from(value: Ciphersuite) -> Self {
        (value as u16)
            .try_into()
            .expect("ffi Ciphersuite is a subset of mls Ciphersuite")
    }
}

impl From<CiphersuiteName> for Ciphersuite {
    #[inline]
    fn from(value: CiphersuiteName) -> Self {
        (value as u16)
            .try_into()
            .expect("mls Ciphersuite is a subset of ffi Ciphersuite")
    }
}

impl From<Ciphersuite> for MlsCiphersuite {
    #[inline]
    fn from(value: Ciphersuite) -> Self {
        CiphersuiteName::from(value).into()
    }
}

impl From<MlsCiphersuite> for Ciphersuite {
    #[inline]
    fn from(value: MlsCiphersuite) -> Self {
        CiphersuiteName::from(value).into()
    }
}

#[cfg_attr(target_family = "wasm", wasm_bindgen(js_name = ciphersuiteFromU16))]
#[cfg_attr(not(target_family = "wasm"), uniffi::export)]
pub fn ciphersuite_from_u16(discriminant: u16) -> CoreCryptoResult<Ciphersuite> {
    Ciphersuite::try_from(discriminant).map_err(CoreCryptoError::generic())
}

#[cfg_attr(target_family = "wasm", wasm_bindgen(js_name = ciphersuiteDefault))]
#[cfg_attr(not(target_family = "wasm"), uniffi::export)]
pub fn ciphersuite_default() -> Ciphersuite {
    Ciphersuite::default()
}

pub(crate) type Ciphersuites = Vec<Ciphersuite>;

/// Helper function to convert a list of integers into a list of ciphersuites
#[cfg_attr(target_family = "wasm", wasm_bindgen(js_name = ciphersuitesFromU16s))]
#[cfg_attr(not(target_family = "wasm"), uniffi::export)]
pub fn ciphersuites_from_u16s(ids: Vec<u16>) -> CoreCryptoResult<Ciphersuites> {
    ids.iter()
        .copied()
        .map(Ciphersuite::try_from)
        .collect::<Result<_, _>>()
        .map_err(CoreCryptoError::generic())
}

/// The default set of ciphersuites contains one entry, the default ciphersuite.
#[cfg_attr(target_family = "wasm", wasm_bindgen(js_name = ciphersuitesDefault))]
#[cfg_attr(not(target_family = "wasm"), uniffi::export)]
pub fn ciphersuites_default() -> Ciphersuites {
    vec![Ciphersuite::default()]
}
