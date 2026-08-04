//! Cipher Suites in bindings
//!
//! Both wasm-bindgen and uniffi support emitting enums, as long as they directly implement the enum;
//! it doesn't work on newtypes around external enums. We therefore redefine the cipher suites enum
//! here with appropriate annotations such that it gets exported to all relevant bindings.

use core_crypto::{CipherSuite as CryptoCipherSuite, MlsCiphersuite as MlsCipherSuite};

use crate::{CoreCryptoError, CoreCryptoResult};

/// MLS cipher suites
#[allow(non_camel_case_types)]
#[allow(clippy::upper_case_acronyms)]
#[derive(Default, Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, derive_more::TryFrom)]
#[try_from(repr)]
#[repr(u16)]
#[derive(uniffi::Enum)]
pub enum CipherSuite {
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

    /// PQ: ML-KEM-768 + x25519 | AES-GCM 128 | SHA2-256 | Ed25519
    MLS_128_MLKEM768X25519_AES128GCM_SHA256_Ed25519 = 0xF001,

    /// PQ: ML-KEM-768 + x25519 | AES-GCM 256 | SHA2-384 | Ed25519
    MLS_128_MLKEM768X25519_AES256GCM_SHA384_Ed25519 = 0xF002,

    /// PQ: ML-KEM-768 + P256 | AES-GCM 128 | SHA2-256 | P256
    MLS_128_MLKEM768P256_AES128GCM_SHA256_P256 = 0xF003,

    /// PQ: ML-KEM-768 + P256 | AES-GCM 256 | SHA2-384 | P256
    MLS_128_MLKEM768P256_AES256GCM_SHA384_P256 = 0xF004,

    /// PQ: ML-KEM-1024 + P384 | AES-GCM 256 | SHA2-384 | P384
    MLS_192_MLKEM1024P384_AES256GCM_SHA384_P384 = 0xF005,

    /// PQ: ML-KEM-768 | AES-GCM 256 | SHA2-384 | P256
    MLS_128_MLKEM768_AES256GCM_SHA384_P256 = 0xF006,

    /// PQ: ML-KEM-1024 | AES-GCM 256 | SHA2-384 | P384
    MLS_192_MLKEM1024_AES256GCM_SHA384_P384 = 0xF007,

    /// PQ: ML-KEM-768 | AES-GCM 256 | SHA2-384 | ML-DSA-65
    MLS_192_MLKEM768_AES256GCM_SHA384_MLDSA65 = 0xF008,

    /// PQ: ML-KEM-1024 | AES-GCM 256 | SHA2-384 | ML-DSA-87
    MLS_256_MLKEM1024_AES256GCM_SHA384_MLDSA87 = 0xF009,

    /// PQ: ML-KEM-768 | AES-GCM 256 | SHA2-384 | Ed25519
    MLS_128_MLKEM768_AES256GCM_SHA384_Ed25519 = 0xF00A,

    /// PQ: ML-KEM-768 + x25519 | Chacha20Poly1305 | SHA2-384 | ML-DSA-44
    MLS_128_MLKEM768X25519_CHACHA20POLY1305_SHA384_MLDSA44 = 0xF00B,
}

impl From<CipherSuite> for MlsCipherSuite {
    #[inline]
    fn from(value: CipherSuite) -> Self {
        (value as u16)
            .try_into()
            .expect("ffi CipherSuite is a subset of mls CipherSuite")
    }
}

impl From<MlsCipherSuite> for CipherSuite {
    #[inline]
    fn from(value: MlsCipherSuite) -> Self {
        (value as u16)
            .try_into()
            .expect("mls CipherSuite is a subset of ffi CipherSuite")
    }
}

impl From<CipherSuite> for CryptoCipherSuite {
    #[inline]
    fn from(value: CipherSuite) -> Self {
        MlsCipherSuite::from(value).into()
    }
}

impl From<CryptoCipherSuite> for CipherSuite {
    #[inline]
    fn from(value: CryptoCipherSuite) -> Self {
        MlsCipherSuite::from(value).into()
    }
}

/// Construct a cipher suite enum instance from its discriminant.
#[uniffi::export]
pub fn cipher_suite_from_u16(discriminant: u16) -> CoreCryptoResult<CipherSuite> {
    CipherSuite::try_from(discriminant).map_err(CoreCryptoError::generic())
}

/// Get an instance of the default cipher suite.
#[uniffi::export]
pub fn cipher_suite_default() -> CipherSuite {
    CipherSuite::default()
}
