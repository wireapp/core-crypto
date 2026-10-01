//! Implementations of the primitives for which we prefer [graviola] where it is available.
//!
//! [`rustcrypto`] is always compiled and is the only backend on architectures graviola does not
//! support. On those it does support, [`graviola`] is compiled as well, and is used whenever the
//! CPU we are actually running on has the features it requires; see [`graviola_supported`].
//!
//! [graviola]: https://github.com/ctz/graviola

use openmls_traits::types::{AeadType, CryptoError, HashType, SignatureScheme};

#[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
mod graviola;
mod rustcrypto;

/// Whether the CPU we are running on has every feature graviola requires.
///
/// graviola asserts its required CPU features on first use and panics if any is missing, which
/// is not something we can recover from, so we must not call it unless this returns `true`. The
/// result cannot be determined at build time, because it depends on the machine the binary runs
/// on, not the one it was built on.
///
/// This duplicates the list of features graviola requires, and must be kept in sync with it.
/// The authoritative list is `verify_cpu_features` in graviola's `low/x86_64/cpu.rs` (and
/// `low/aarch64/cpu.rs` for aarch64), at the revision pinned in `crypto/Cargo.toml`, e.g.
/// <https://github.com/ctz/graviola/blob/1a9dfcde985638c05b8fe192639c2e7a8ca763dc/graviola/src/low/x86_64/cpu.rs>.
#[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
fn graviola_supported() -> bool {
    static SUPPORTED: std::sync::LazyLock<bool> = std::sync::LazyLock::new(detect_graviola_support);
    *SUPPORTED
}

#[cfg(target_arch = "x86_64")]
fn detect_graviola_support() -> bool {
    std::is_x86_feature_detected!("aes")
        && std::is_x86_feature_detected!("pclmulqdq")
        && std::is_x86_feature_detected!("bmi1")
        && std::is_x86_feature_detected!("adx")
        && std::is_x86_feature_detected!("avx")
        && std::is_x86_feature_detected!("avx2")
}

#[cfg(target_arch = "aarch64")]
fn detect_graviola_support() -> bool {
    std::arch::is_aarch64_feature_detected!("neon")
        && std::arch::is_aarch64_feature_detected!("aes")
        && std::arch::is_aarch64_feature_detected!("pmull")
        && std::arch::is_aarch64_feature_detected!("sha2")
}

/// Call `$f` on the graviola backend if it is available here, and on the rustcrypto backend
/// otherwise.
macro_rules! dispatch {
    ($f:ident($($arg:expr),* $(,)?)) => {{
        #[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
        if graviola_supported() {
            return graviola::$f($($arg),*);
        }
        rustcrypto::$f($($arg),*)
    }};
}

pub(super) fn hash(hash_type: HashType, data: &[u8]) -> Result<Vec<u8>, CryptoError> {
    dispatch!(hash(hash_type, data))
}

pub(super) fn aead_encrypt(
    alg: AeadType,
    key: &[u8],
    data: &[u8],
    nonce: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    dispatch!(aead_encrypt(alg, key, data, nonce, aad))
}

pub(super) fn aead_decrypt(
    alg: AeadType,
    key: &[u8],
    ct_tag: &[u8],
    nonce: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    dispatch!(aead_decrypt(alg, key, ct_tag, nonce, aad))
}

pub(super) fn signature_key_gen(
    alg: SignatureScheme,
    rng: &mut rand_chacha::ChaCha20Rng,
) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
    dispatch!(signature_key_gen(alg, rng))
}

pub(super) fn validate_signature_key(alg: SignatureScheme, key: &[u8]) -> Result<(), CryptoError> {
    dispatch!(validate_signature_key(alg, key))
}

pub(super) fn verify_signature(
    alg: SignatureScheme,
    data: &[u8],
    pk: &[u8],
    signature: &[u8],
) -> Result<(), CryptoError> {
    dispatch!(verify_signature(alg, data, pk, signature))
}
