//! Signature schemes in bindings
//!
//! We can emit enums, as long as they are directly implemented in the FFI crate;
//! it doesn't work on newtypes around external enums. We therefore redefine the signature schemes enum
//! here with appropriate annotations such that it gets exported to all relevant bindings.

use core_crypto::SignatureScheme as MlsSignatureScheme;

/// Signature schemes supported by MLS, as defined in RFC 9420.
#[allow(non_camel_case_types)]
#[allow(clippy::upper_case_acronyms)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, derive_more::TryFrom)]
#[try_from(repr)]
#[repr(u16)]
#[derive(uniffi::Enum)]
pub enum SignatureScheme {
    /// ECDSA with secp256r1 (P-256) and SHA-256
    ECDSA_SECP256R1_SHA256 = 0x0403,
    /// ECDSA with secp384r1 (P-384) and SHA-384
    ECDSA_SECP384R1_SHA384 = 0x0503,
    /// ECDSA with secp521r1 (P-521) and SHA-512
    ECDSA_SECP521R1_SHA512 = 0x0603,
    /// Deterministic EdDSA with Curve25519 (Ed25519)
    ED25519 = 0x0807,
    /// Deterministic EdDSA with Curve448 (Ed448)
    ED448 = 0x0808,
}

impl From<SignatureScheme> for MlsSignatureScheme {
    #[inline]
    fn from(value: SignatureScheme) -> Self {
        (value as u16)
            .try_into()
            .expect("ffi SignatureScheme is a subset of mls SignatureScheme")
    }
}

impl From<MlsSignatureScheme> for SignatureScheme {
    #[inline]
    fn from(value: MlsSignatureScheme) -> Self {
        (value as u16)
            .try_into()
            .expect("mls SignatureScheme is a subset of ffi SignatureScheme")
    }
}
