//! Implementations of the primitives, chosen at build time.
//!
//! [`rustcrypto`] is always compiled. It is the backend in the browser, and for now everywhere
//! else too.

use openmls_traits::types::{
    AeadType, CryptoError, HashType, HpkeCiphertext, HpkeConfig, HpkeKeyPair, SignatureScheme,
};
use tls_codec::SecretVLBytes;

#[cfg_attr(not(test), expect(dead_code, reason = "no backend uses the HPKE core yet"))]
pub(crate) mod hpke;
mod rustcrypto;

/// Call `$f` on the backend for this build.
macro_rules! dispatch {
    ($f:ident($($arg:expr),* $(,)?)) => {
        rustcrypto::$f($($arg),*)
    };
}

pub(super) fn hash(hash_type: HashType, data: &[u8]) -> Result<Vec<u8>, CryptoError> {
    dispatch!(hash(hash_type, data))
}

pub(super) fn hkdf_extract(hash_type: HashType, salt: &[u8], ikm: &[u8]) -> Result<SecretVLBytes, CryptoError> {
    dispatch!(hkdf_extract(hash_type, salt, ikm))
}

pub(super) fn hkdf_expand(
    hash_type: HashType,
    prk: &[u8],
    info: &[u8],
    okm_len: usize,
) -> Result<SecretVLBytes, CryptoError> {
    dispatch!(hkdf_expand(hash_type, prk, info, okm_len))
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

pub(super) fn sign(alg: SignatureScheme, data: &[u8], key: &[u8]) -> Result<Vec<u8>, CryptoError> {
    dispatch!(sign(alg, data, key))
}

pub(super) fn hpke_seal(
    config: &HpkeConfig,
    pk_r: &[u8],
    info: &[u8],
    aad: &[u8],
    psk: hpke::Psk<'_>,
    ptxt: &[u8],
    rng: &mut rand_chacha::ChaCha20Rng,
) -> Result<HpkeCiphertext, CryptoError> {
    dispatch!(hpke_seal(config, pk_r, info, aad, psk, ptxt, rng))
}

pub(super) fn hpke_open(
    config: &HpkeConfig,
    sk_r: &[u8],
    enc: &[u8],
    info: &[u8],
    aad: &[u8],
    psk: hpke::Psk<'_>,
    ciphertext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    dispatch!(hpke_open(config, sk_r, enc, info, aad, psk, ciphertext))
}

pub(super) fn hpke_export_tx(
    config: &HpkeConfig,
    pk_r: &[u8],
    info: &[u8],
    exporter_context: &[u8],
    len: usize,
    rng: &mut rand_chacha::ChaCha20Rng,
) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
    dispatch!(hpke_export_tx(config, pk_r, info, exporter_context, len, rng))
}

pub(super) fn hpke_export_rx(
    config: &HpkeConfig,
    enc: &[u8],
    sk_r: &[u8],
    info: &[u8],
    exporter_context: &[u8],
    len: usize,
) -> Result<Vec<u8>, CryptoError> {
    dispatch!(hpke_export_rx(config, enc, sk_r, info, exporter_context, len))
}

pub(super) fn hpke_derive_keypair(config: &HpkeConfig, ikm: &[u8]) -> Result<HpkeKeyPair, CryptoError> {
    dispatch!(hpke_derive_keypair(config, ikm))
}
