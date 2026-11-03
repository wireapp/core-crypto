//! The RustCrypto implementation of the primitives. This is always compiled: it is the only
//! backend in the browser, where aws-lc cannot be built, and the fallback for what aws-lc-rs does
//! not offer.

use aes_gcm::{
    Aes128Gcm, Aes256Gcm, KeyInit,
    aead::{Aead, Nonce, Payload},
};
use chacha20poly1305::ChaCha20Poly1305;
use crypto_common::KeySizeUser as _;
use elliptic_curve::Generate as _;
use hkdf::Hkdf;
use ml_dsa::{MlDsa44, MlDsa65, MlDsa87};
use openmls_traits::{
    mldsa,
    types::{
        AeadType, CryptoError, HashType, HpkeAeadType, HpkeCiphertext, HpkeConfig, HpkeKdfType, HpkeKemType,
        HpkeKeyPair, SignatureScheme,
    },
};
use sha2::{Digest as _, Sha256, Sha384, Sha512};
use tls_codec::SecretVLBytes;

use super::hpke::Psk;

pub(crate) fn hash(hash_type: HashType, data: &[u8]) -> Result<Vec<u8>, CryptoError> {
    match hash_type {
        HashType::Sha2_256 => Ok(Sha256::digest(data).as_slice().into()),
        HashType::Sha2_384 => Ok(Sha384::digest(data).as_slice().into()),
        HashType::Sha2_512 => Ok(Sha512::digest(data).as_slice().into()),
    }
}

pub(crate) fn aead_encrypt(
    alg: AeadType,
    key: &[u8],
    data: &[u8],
    nonce: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    // All supported algorithms use the same nonce size of 96 bits, so
    // picking any of them for the generic parameter of Nonce<A> is fine.
    let nonce = Nonce::<Aes128Gcm>::try_from(nonce).map_err(|_| CryptoError::InvalidLength)?;

    match alg {
        AeadType::Aes128Gcm => {
            let aes = Aes128Gcm::new_from_slice(key).map_err(|_| CryptoError::CryptoLibraryError)?;

            aes.encrypt(&nonce, Payload { msg: data, aad })
                .map(|r| r.as_slice().into())
                .map_err(|_| CryptoError::CryptoLibraryError)
        }
        AeadType::Aes256Gcm => {
            let aes = Aes256Gcm::new_from_slice(key).map_err(|_| CryptoError::CryptoLibraryError)?;

            aes.encrypt(&nonce, Payload { msg: data, aad })
                .map(|r| r.as_slice().into())
                .map_err(|_| CryptoError::CryptoLibraryError)
        }
        AeadType::ChaCha20Poly1305 => {
            let chacha_poly = ChaCha20Poly1305::new_from_slice(key).map_err(|_| CryptoError::CryptoLibraryError)?;

            chacha_poly
                .encrypt(&nonce, Payload { msg: data, aad })
                .map(|r| r.as_slice().into())
                .map_err(|_| CryptoError::CryptoLibraryError)
        }
    }
}

pub(crate) fn aead_decrypt(
    alg: AeadType,
    key: &[u8],
    ct_tag: &[u8],
    nonce: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    // All supported algorithms use the same nonce size of 96 bits, so
    // picking any of them for the generic parameter of Nonce<A> is fine.
    let nonce = Nonce::<Aes128Gcm>::try_from(nonce).map_err(|_| CryptoError::InvalidLength)?;

    match alg {
        AeadType::Aes128Gcm => {
            let aes = Aes128Gcm::new_from_slice(key).map_err(|_| CryptoError::CryptoLibraryError)?;
            aes.decrypt(&nonce, Payload { msg: ct_tag, aad })
                .map(|r| r.as_slice().into())
                .map_err(|_| CryptoError::AeadDecryptionError)
        }
        AeadType::Aes256Gcm => {
            let aes = Aes256Gcm::new_from_slice(key).map_err(|_| CryptoError::CryptoLibraryError)?;
            aes.decrypt(&nonce, Payload { msg: ct_tag, aad })
                .map(|r| r.as_slice().into())
                .map_err(|_| CryptoError::AeadDecryptionError)
        }
        AeadType::ChaCha20Poly1305 => {
            let chacha_poly = ChaCha20Poly1305::new_from_slice(key).map_err(|_| CryptoError::CryptoLibraryError)?;
            chacha_poly
                .decrypt(&nonce, Payload { msg: ct_tag, aad })
                .map(|r| r.as_slice().into())
                .map_err(|_| CryptoError::AeadDecryptionError)
        }
    }
}

pub(crate) fn hkdf_extract(hash_type: HashType, salt: &[u8], ikm: &[u8]) -> Result<SecretVLBytes, CryptoError> {
    match hash_type {
        HashType::Sha2_256 => Ok(Hkdf::<Sha256>::extract(Some(salt), ikm).0.as_slice().into()),
        HashType::Sha2_384 => Ok(Hkdf::<Sha384>::extract(Some(salt), ikm).0.as_slice().into()),
        HashType::Sha2_512 => Ok(Hkdf::<Sha512>::extract(Some(salt), ikm).0.as_slice().into()),
    }
}

pub(crate) fn hkdf_expand(
    hash_type: HashType,
    prk: &[u8],
    info: &[u8],
    okm_len: usize,
) -> Result<SecretVLBytes, CryptoError> {
    match hash_type {
        HashType::Sha2_256 => {
            let hkdf = Hkdf::<Sha256>::from_prk(prk).map_err(|_| CryptoError::HkdfOutputLengthInvalid)?;

            let mut okm = vec![0u8; okm_len];
            hkdf.expand(info, &mut okm)
                .map_err(|_| CryptoError::HkdfOutputLengthInvalid)?;

            Ok(okm.into())
        }
        HashType::Sha2_384 => {
            let hkdf = Hkdf::<Sha384>::from_prk(prk).map_err(|_| CryptoError::HkdfOutputLengthInvalid)?;

            let mut okm = vec![0u8; okm_len];
            hkdf.expand(info, &mut okm)
                .map_err(|_| CryptoError::HkdfOutputLengthInvalid)?;

            Ok(okm.into())
        }
        HashType::Sha2_512 => {
            let hkdf = Hkdf::<Sha512>::from_prk(prk).map_err(|_| CryptoError::HkdfOutputLengthInvalid)?;

            let mut okm = vec![0u8; okm_len];
            hkdf.expand(info, &mut okm)
                .map_err(|_| CryptoError::HkdfOutputLengthInvalid)?;

            Ok(okm.into())
        }
    }
}

/// Generate a `(secret key, public key)` pair from a signature scheme.
pub(crate) fn signature_key_gen(
    alg: SignatureScheme,
    rng: &mut rand_chacha::ChaCha20Rng,
) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
    match alg {
        SignatureScheme::ECDSA_SECP256R1_SHA256 => {
            let sk = p256::ecdsa::SigningKey::generate_from_rng(rng);
            let pk = sk.verifying_key().to_sec1_bytes().to_vec();
            Ok((sk.to_bytes().to_vec(), pk))
        }
        SignatureScheme::ECDSA_SECP384R1_SHA384 => {
            let sk = p384::ecdsa::SigningKey::generate_from_rng(rng);
            let pk = sk.verifying_key().to_sec1_bytes().to_vec();
            Ok((sk.to_bytes().to_vec(), pk))
        }
        SignatureScheme::ECDSA_SECP521R1_SHA512 => {
            let sk = p521::ecdsa::SigningKey::generate_from_rng(rng);
            let pk = p521::ecdsa::VerifyingKey::from(&sk)
                .to_sec1_point(false)
                .to_bytes()
                .into();
            Ok((sk.to_bytes().to_vec(), pk))
        }
        SignatureScheme::ED25519 => {
            let k = ed25519_dalek::SigningKey::generate(rng);
            let pk = k.verifying_key();
            Ok((k.to_bytes().into(), pk.to_bytes().into()))
        }
        SignatureScheme::MLDSA44 => mldsa::key_gen::<MlDsa44>(rng),
        SignatureScheme::MLDSA65 => mldsa::key_gen::<MlDsa65>(rng),
        SignatureScheme::MLDSA87 => mldsa::key_gen::<MlDsa87>(rng),
        _ => Err(CryptoError::UnsupportedSignatureScheme),
    }
}

pub(crate) fn validate_signature_key(alg: SignatureScheme, key: &[u8]) -> Result<(), CryptoError> {
    match alg {
        SignatureScheme::ED25519 => {
            ed25519_dalek::VerifyingKey::try_from(key).map_err(|_| CryptoError::InvalidKey)?;
        }
        SignatureScheme::ECDSA_SECP256R1_SHA256 => {
            p256::ecdsa::VerifyingKey::try_from(key).map_err(|_| CryptoError::InvalidKey)?;
        }
        SignatureScheme::ECDSA_SECP384R1_SHA384 => {
            p384::ecdsa::VerifyingKey::try_from(key).map_err(|_| CryptoError::InvalidKey)?;
        }
        SignatureScheme::ECDSA_SECP521R1_SHA512 => {
            p521::ecdsa::VerifyingKey::from_sec1_bytes(key).map_err(|_| CryptoError::InvalidKey)?;
        }
        SignatureScheme::ED448 => {
            return Err(CryptoError::UnsupportedSignatureScheme);
        }
        SignatureScheme::MLDSA44 => {
            (ml_dsa::VerifyingKey::<MlDsa44>::key_size() == key.len()).ok_or(CryptoError::InvalidKey)?
        }
        SignatureScheme::MLDSA65 => {
            (ml_dsa::VerifyingKey::<MlDsa65>::key_size() == key.len()).ok_or(CryptoError::InvalidKey)?
        }
        SignatureScheme::MLDSA87 => {
            (ml_dsa::VerifyingKey::<MlDsa87>::key_size() == key.len()).ok_or(CryptoError::InvalidKey)?
        }
    }
    Ok(())
}

pub(crate) fn verify_signature(
    alg: SignatureScheme,
    data: &[u8],
    pk: &[u8],
    signature: &[u8],
) -> Result<(), CryptoError> {
    use signature::Verifier as _;
    match alg {
        SignatureScheme::ECDSA_SECP256R1_SHA256 => {
            let k = p256::ecdsa::VerifyingKey::from_sec1_bytes(pk).map_err(|_| CryptoError::CryptoLibraryError)?;

            let signature =
                p256::ecdsa::DerSignature::from_bytes(signature).map_err(|_| CryptoError::InvalidSignature)?;

            k.verify(data, &signature).map_err(|_| CryptoError::InvalidSignature)
        }
        SignatureScheme::ECDSA_SECP384R1_SHA384 => {
            let k = p384::ecdsa::VerifyingKey::from_sec1_bytes(pk).map_err(|_| CryptoError::CryptoLibraryError)?;

            let signature =
                p384::ecdsa::DerSignature::from_bytes(signature).map_err(|_| CryptoError::InvalidSignature)?;

            k.verify(data, &signature).map_err(|_| CryptoError::InvalidSignature)
        }
        SignatureScheme::ECDSA_SECP521R1_SHA512 => {
            let k = p521::ecdsa::VerifyingKey::from_sec1_bytes(pk).map_err(|_| CryptoError::CryptoLibraryError)?;

            let signature = p521::ecdsa::Signature::from_der(signature).map_err(|_| CryptoError::InvalidSignature)?;

            k.verify(data, &signature).map_err(|_| CryptoError::InvalidSignature)
        }
        SignatureScheme::ED25519 => {
            let k = ed25519_dalek::VerifyingKey::try_from(pk).map_err(|_| CryptoError::CryptoLibraryError)?;

            let sig = ed25519_dalek::Signature::from_slice(signature).map_err(|_| CryptoError::InvalidSignature)?;

            k.verify_strict(data, &sig).map_err(|_| CryptoError::InvalidSignature)
        }
        SignatureScheme::MLDSA44 => mldsa::verify::<MlDsa44>(data, pk, signature),
        SignatureScheme::MLDSA65 => mldsa::verify::<MlDsa65>(data, pk, signature),
        SignatureScheme::MLDSA87 => mldsa::verify::<MlDsa87>(data, pk, signature),
        _ => Err(CryptoError::UnsupportedSignatureScheme),
    }
}

/// Sign `data` with the private key `key`.
///
/// This is the signer from openmls' `DefaultSigner`, which used to do all our signing, so the
/// output is unchanged: ECDSA signatures are deterministic (RFC 6979) and DER-encoded, and Ed25519
/// accepts both a 32-byte seed and the legacy 64-byte `seed || public key` encoding.
pub(crate) fn sign(alg: SignatureScheme, data: &[u8], key: &[u8]) -> Result<Vec<u8>, CryptoError> {
    use signature::Signer as _;
    match alg {
        SignatureScheme::ECDSA_SECP256R1_SHA256 => {
            let k = p256::ecdsa::SigningKey::from_slice(key).map_err(|_| CryptoError::InvalidKey)?;
            let signature: p256::ecdsa::Signature = k.try_sign(data).map_err(|_| CryptoError::CryptoLibraryError)?;
            Ok(signature.to_der().to_bytes().into())
        }
        SignatureScheme::ECDSA_SECP384R1_SHA384 => {
            let k = p384::ecdsa::SigningKey::from_slice(key).map_err(|_| CryptoError::InvalidKey)?;
            let signature: p384::ecdsa::Signature = k.try_sign(data).map_err(|_| CryptoError::CryptoLibraryError)?;
            Ok(signature.to_der().to_bytes().into())
        }
        SignatureScheme::ECDSA_SECP521R1_SHA512 => {
            let k = p521::ecdsa::SigningKey::from_slice(key).map_err(|_| CryptoError::InvalidKey)?;
            let signature: p521::ecdsa::Signature = k.try_sign(data).map_err(|_| CryptoError::CryptoLibraryError)?;
            Ok(signature.to_der().to_bytes().into())
        }
        SignatureScheme::ED25519 => {
            let k = ed25519_signing_key(key)?;
            let signature = k.try_sign(data).map_err(|_| CryptoError::CryptoLibraryError)?;
            Ok(signature.to_bytes().into())
        }
        SignatureScheme::MLDSA44 => mldsa::sign::<MlDsa44>(data, key),
        SignatureScheme::MLDSA65 => mldsa::sign::<MlDsa65>(data, key),
        SignatureScheme::MLDSA87 => mldsa::sign::<MlDsa87>(data, key),
        _ => Err(CryptoError::UnsupportedSignatureScheme),
    }
}

/// Load an Ed25519 signing key from either a 32-byte seed or the legacy 64-byte
/// `seed || public key` encoding, which older keystores still contain.
fn ed25519_signing_key(key: &[u8]) -> Result<ed25519_dalek::SigningKey, CryptoError> {
    match key.len() {
        ed25519_dalek::KEYPAIR_LENGTH => {
            let mut keypair = zeroize::Zeroizing::new([0u8; ed25519_dalek::KEYPAIR_LENGTH]);
            keypair.copy_from_slice(key);
            ed25519_dalek::SigningKey::from_keypair_bytes(&keypair).map_err(|_| CryptoError::InvalidKey)
        }
        ed25519_dalek::SECRET_KEY_LENGTH => {
            let mut seed = zeroize::Zeroizing::new([0u8; ed25519_dalek::SECRET_KEY_LENGTH]);
            seed.copy_from_slice(key);
            Ok(ed25519_dalek::SigningKey::from_bytes(&seed))
        }
        _ => Err(CryptoError::InvalidKey),
    }
}

// HPKE, through the `hpke` crate. This is the only backend for the post-quantum KEMs, and for
// the DH KEMs it is the reference that the HPKE core in `super::hpke` is tested against.

macro_rules! hpke_dispatch {
    ($config:expr, $f:ident $(, $arg:expr)* $(,)?) => {
        match $config {
            HpkeConfig(HpkeKemType::DhKem25519, HpkeKdfType::HkdfSha256, HpkeAeadType::AesGcm128) =>
                hpke_core::$f::<hpke::aead::AesGcm128, hpke::kdf::HkdfSha256, hpke::kem::X25519HkdfSha256>($($arg),*),
            HpkeConfig(HpkeKemType::DhKem25519, HpkeKdfType::HkdfSha256, HpkeAeadType::ChaCha20Poly1305) =>
                hpke_core::$f::<hpke::aead::ChaCha20Poly1305, hpke::kdf::HkdfSha256, hpke::kem::X25519HkdfSha256>($($arg),*),
            HpkeConfig(HpkeKemType::DhKemP256, HpkeKdfType::HkdfSha256, HpkeAeadType::AesGcm128) =>
                hpke_core::$f::<hpke::aead::AesGcm128, hpke::kdf::HkdfSha256, hpke::kem::DhP256HkdfSha256>($($arg),*),
            HpkeConfig(HpkeKemType::DhKemP384, HpkeKdfType::HkdfSha384, HpkeAeadType::AesGcm256) =>
                hpke_core::$f::<hpke::aead::AesGcm256, hpke::kdf::HkdfSha384, hpke::kem::DhP384HkdfSha384>($($arg),*),
            HpkeConfig(HpkeKemType::DhKemP521, HpkeKdfType::HkdfSha512, HpkeAeadType::AesGcm256) =>
                hpke_core::$f::<hpke::aead::AesGcm256, hpke::kdf::HkdfSha512, hpke::kem::DhP521HkdfSha512>($($arg),*),
            HpkeConfig(HpkeKemType::MlKem768X25519, HpkeKdfType::HkdfSha256, HpkeAeadType::AesGcm128) =>
                hpke_core::$f::<hpke::aead::AesGcm128, hpke::kdf::HkdfSha256, hpke::kem::XWing>($($arg),*),
            HpkeConfig(HpkeKemType::MlKem768X25519, HpkeKdfType::HkdfSha384, HpkeAeadType::AesGcm256) =>
                hpke_core::$f::<hpke::aead::AesGcm256, hpke::kdf::HkdfSha384, hpke::kem::XWing>($($arg),*),
            HpkeConfig(HpkeKemType::MlKem768X25519, HpkeKdfType::HkdfSha384, HpkeAeadType::ChaCha20Poly1305) =>
                hpke_core::$f::<hpke::aead::ChaCha20Poly1305, hpke::kdf::HkdfSha384, hpke::kem::XWing>($($arg),*),
            HpkeConfig(HpkeKemType::MlKem768P256, HpkeKdfType::HkdfSha256, HpkeAeadType::AesGcm128) =>
                hpke_core::$f::<hpke::aead::AesGcm128, hpke::kdf::HkdfSha256, hpke::kem::MlKem768P256>($($arg),*),
            HpkeConfig(HpkeKemType::MlKem768P256, HpkeKdfType::HkdfSha384, HpkeAeadType::AesGcm256) =>
                hpke_core::$f::<hpke::aead::AesGcm256, hpke::kdf::HkdfSha384, hpke::kem::MlKem768P256>($($arg),*),
            HpkeConfig(HpkeKemType::MlKem1024P384, HpkeKdfType::HkdfSha384, HpkeAeadType::AesGcm256) =>
                hpke_core::$f::<hpke::aead::AesGcm256, hpke::kdf::HkdfSha384, hpke::kem::MlKem1024P384>($($arg),*),
            HpkeConfig(HpkeKemType::MlKem768, HpkeKdfType::HkdfSha384, HpkeAeadType::AesGcm256) =>
                hpke_core::$f::<hpke::aead::AesGcm256, hpke::kdf::HkdfSha384, hpke::kem::MlKem768>($($arg),*),
            HpkeConfig(HpkeKemType::MlKem1024, HpkeKdfType::HkdfSha384, HpkeAeadType::AesGcm256) =>
                hpke_core::$f::<hpke::aead::AesGcm256, hpke::kdf::HkdfSha384, hpke::kem::MlKem1024>($($arg),*),
            _ => Err(CryptoError::UnsupportedKem),
        }
    };
}

macro_rules! hpke_kem_dispatch {
    ($kem:expr, $f:ident $(, $arg:expr)* $(,)?) => {
        match $kem {
            HpkeKemType::DhKem25519 => hpke_core::$f::<hpke::kem::X25519HkdfSha256>($($arg),*),
            HpkeKemType::DhKemP256 => hpke_core::$f::<hpke::kem::DhP256HkdfSha256>($($arg),*),
            HpkeKemType::DhKemP384 => hpke_core::$f::<hpke::kem::DhP384HkdfSha384>($($arg),*),
            HpkeKemType::DhKemP521 => hpke_core::$f::<hpke::kem::DhP521HkdfSha512>($($arg),*),
            HpkeKemType::MlKem768X25519 => hpke_core::$f::<hpke::kem::XWing>($($arg),*),
            HpkeKemType::MlKem768P256 => hpke_core::$f::<hpke::kem::MlKem768P256>($($arg),*),
            HpkeKemType::MlKem1024P384 => hpke_core::$f::<hpke::kem::MlKem1024P384>($($arg),*),
            HpkeKemType::MlKem768 => hpke_core::$f::<hpke::kem::MlKem768>($($arg),*),
            HpkeKemType::MlKem1024 => hpke_core::$f::<hpke::kem::MlKem1024>($($arg),*),
            HpkeKemType::DhKem448 => Err(CryptoError::UnsupportedKem),
        }
    };
}

/// Single-shot HPKE seal, in base mode or, given a PSK, PSK mode.
pub(crate) fn hpke_seal(
    config: &HpkeConfig,
    pk_r: &[u8],
    info: &[u8],
    aad: &[u8],
    psk: Psk<'_>,
    ptxt: &[u8],
    rng: &mut rand_chacha::ChaCha20Rng,
) -> Result<HpkeCiphertext, CryptoError> {
    match psk {
        None => hpke_dispatch!(config, hpke_seal, pk_r, info, aad, ptxt, rng),
        Some((psk, psk_id)) => hpke_dispatch!(config, hpke_seal_psk, pk_r, info, aad, psk, psk_id, ptxt, rng),
    }
}

/// Single-shot HPKE open, in base mode or, given a PSK, PSK mode.
pub(crate) fn hpke_open(
    config: &HpkeConfig,
    sk_r: &[u8],
    enc: &[u8],
    info: &[u8],
    aad: &[u8],
    psk: Psk<'_>,
    ciphertext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    match psk {
        None => hpke_dispatch!(config, hpke_open, sk_r, enc, info, aad, ciphertext),
        Some((psk, psk_id)) => hpke_dispatch!(config, hpke_open_psk, sk_r, enc, info, aad, psk, psk_id, ciphertext),
    }
}

/// Set up a base-mode HPKE sender and export a secret, returning `(enc, secret)`.
pub(crate) fn hpke_export_tx(
    config: &HpkeConfig,
    pk_r: &[u8],
    info: &[u8],
    exporter_context: &[u8],
    len: usize,
    rng: &mut rand_chacha::ChaCha20Rng,
) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
    hpke_dispatch!(config, hpke_export_tx, pk_r, info, exporter_context, len, rng)
}

/// Set up a base-mode HPKE receiver and export a secret.
pub(crate) fn hpke_export_rx(
    config: &HpkeConfig,
    enc: &[u8],
    sk_r: &[u8],
    info: &[u8],
    exporter_context: &[u8],
    len: usize,
) -> Result<Vec<u8>, CryptoError> {
    hpke_dispatch!(config, hpke_export_rx, enc, sk_r, info, exporter_context, len)
}

/// HPKE `DeriveKeyPair` for the KEM of `config`.
pub(crate) fn hpke_derive_keypair(config: &HpkeConfig, ikm: &[u8]) -> Result<HpkeKeyPair, CryptoError> {
    hpke_kem_dispatch!(config.0, hpke_derive_keypair, ikm)
}

mod hpke_core {
    use hpke::PskBundle;
    use openmls_traits::types::{CryptoError, HpkeCiphertext, HpkeKeyPair};

    pub(crate) fn hpke_open<Aead: hpke::aead::Aead, Kdf: hpke::kdf::Kdf, Kem: hpke::Kem>(
        private_key: &[u8],
        kem_output: &[u8],
        info: &[u8],
        aad: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        use hpke::Deserializable as _;
        let encapped_key = Kem::EncappedKey::from_bytes(kem_output).map_err(|_| CryptoError::HpkeDecryptionError)?;
        let key = Kem::PrivateKey::from_bytes(private_key).map_err(|_| CryptoError::HpkeDecryptionError)?;
        let plaintext =
            hpke::single_shot_open::<Aead, Kdf, Kem>(&hpke::OpModeR::Base, &key, &encapped_key, info, ciphertext, aad)
                .map_err(|_| CryptoError::HpkeDecryptionError)?;

        Ok(plaintext)
    }

    pub(crate) fn hpke_open_psk<Aead: hpke::aead::Aead, Kdf: hpke::kdf::Kdf, Kem: hpke::Kem>(
        private_key: &[u8],
        kem_output: &[u8],
        info: &[u8],
        aad: &[u8],
        psk: &[u8],
        psk_id: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        use hpke::Deserializable as _;
        let encapped_key = Kem::EncappedKey::from_bytes(kem_output).map_err(|_| CryptoError::HpkeDecryptionError)?;
        let key = Kem::PrivateKey::from_bytes(private_key).map_err(|_| CryptoError::HpkeDecryptionError)?;
        let psk_bundle = PskBundle::new(psk, psk_id).map_err(|_| CryptoError::HpkeDecryptionError)?;
        let plaintext = hpke::single_shot_open::<Aead, Kdf, Kem>(
            &hpke::OpModeR::Psk(psk_bundle),
            &key,
            &encapped_key,
            info,
            ciphertext,
            aad,
        )
        .map_err(|_| CryptoError::HpkeDecryptionError)?;

        Ok(plaintext)
    }

    pub(crate) fn hpke_seal<Aead: hpke::aead::Aead, Kdf: hpke::kdf::Kdf, Kem: hpke::Kem>(
        public_key: &[u8],
        info: &[u8],
        aad: &[u8],
        plaintext: &[u8],
        csprng: &mut impl rand_core::CryptoRng,
    ) -> Result<HpkeCiphertext, CryptoError> {
        use hpke::{Deserializable as _, Serializable as _};
        let key = Kem::PublicKey::from_bytes(public_key).map_err(|_| CryptoError::HpkeEncryptionError)?;
        let (encapped, ciphertext) =
            hpke::single_shot_seal_with_rng::<Aead, Kdf, Kem>(&hpke::OpModeS::Base, &key, info, plaintext, aad, csprng)
                .map_err(|_| CryptoError::HpkeEncryptionError)?;

        Ok(HpkeCiphertext {
            kem_output: encapped.to_bytes().to_vec().into(),
            ciphertext: ciphertext.into(),
        })
    }

    pub(crate) fn hpke_seal_psk<Aead: hpke::aead::Aead, Kdf: hpke::kdf::Kdf, Kem: hpke::Kem>(
        public_key: &[u8],
        info: &[u8],
        aad: &[u8],
        psk: &[u8],
        psk_id: &[u8],
        plaintext: &[u8],
        csprng: &mut impl rand_core::CryptoRng,
    ) -> Result<HpkeCiphertext, CryptoError> {
        use hpke::{Deserializable as _, Serializable as _};
        let key = Kem::PublicKey::from_bytes(public_key).map_err(|_| CryptoError::HpkeEncryptionError)?;
        let psk_bundle = PskBundle::new(psk, psk_id).map_err(|_| CryptoError::HpkeEncryptionError)?;
        let (encapped, ciphertext) = hpke::single_shot_seal_with_rng::<Aead, Kdf, Kem>(
            &hpke::OpModeS::Psk(psk_bundle),
            &key,
            info,
            plaintext,
            aad,
            csprng,
        )
        .map_err(|_| CryptoError::HpkeEncryptionError)?;

        Ok(HpkeCiphertext {
            kem_output: encapped.to_bytes().to_vec().into(),
            ciphertext: ciphertext.into(),
        })
    }

    #[expect(dead_code)]
    pub(crate) fn hpke_gen_keypair<Kem: hpke::Kem>(
        csprng: &mut impl rand_core::CryptoRng,
    ) -> Result<HpkeKeyPair, CryptoError> {
        use hpke::Serializable as _;
        let (sk, pk) = Kem::gen_keypair_with_rng(csprng);
        let (private, public) = (sk.to_bytes().to_vec().into(), pk.to_bytes().to_vec());

        Ok(HpkeKeyPair { private, public })
    }

    pub(crate) fn hpke_derive_keypair<Kem: hpke::Kem>(ikm: &[u8]) -> Result<HpkeKeyPair, CryptoError> {
        use hpke::Serializable as _;
        let (sk, pk) = Kem::derive_keypair(ikm);
        let (private, public) = (sk.to_bytes().to_vec().into(), pk.to_bytes().to_vec());

        Ok(HpkeKeyPair { private, public })
    }

    pub(crate) fn hpke_export_rx<Aead: hpke::aead::Aead, Kdf: hpke::kdf::Kdf, Kem: hpke::Kem>(
        encapped_key: &[u8],
        rx_private_key: &[u8],
        info: &[u8],
        export_info: &[u8],
        export_len: usize,
    ) -> Result<Vec<u8>, CryptoError> {
        use hpke::Deserializable as _;
        let key = Kem::PrivateKey::from_bytes(rx_private_key).map_err(|_| CryptoError::ReceiverSetupError)?;
        let encapped_key = Kem::EncappedKey::from_bytes(encapped_key).map_err(|_| CryptoError::ReceiverSetupError)?;
        let ctx = hpke::setup_receiver::<Aead, Kdf, Kem>(&hpke::OpModeR::Base, &key, &encapped_key, info)
            .map_err(|_| CryptoError::ReceiverSetupError)?;

        let mut export = vec![0u8; export_len];

        ctx.export(export_info, &mut export)
            .map_err(|_| CryptoError::ExporterError)?;

        Ok(export)
    }

    pub(crate) fn hpke_export_tx<Aead: hpke::aead::Aead, Kdf: hpke::kdf::Kdf, Kem: hpke::Kem>(
        tx_public_key: &[u8],
        info: &[u8],
        export_info: &[u8],
        export_len: usize,
        csprng: &mut impl rand_core::CryptoRng,
    ) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
        use hpke::{Deserializable as _, Serializable as _};
        let key = Kem::PublicKey::from_bytes(tx_public_key).map_err(|_| CryptoError::SenderSetupError)?;
        let (kem_output, ctx) = hpke::setup_sender_with_rng::<Aead, Kdf, Kem>(&hpke::OpModeS::Base, &key, info, csprng)
            .map_err(|_| CryptoError::SenderSetupError)?;

        let mut export = vec![0u8; export_len];

        ctx.export(export_info, &mut export)
            .map_err(|_| CryptoError::ExporterError)?;

        Ok((kem_output.to_bytes().to_vec(), export))
    }
}

#[cfg(test)]
mod tests {
    use openmls_basic_credential::SignatureKeyPair;
    use openmls_traits::{signatures::Signer as _, types::SignatureScheme};
    use rand_core::SeedableRng as _;

    /// Signing used to go through openmls' `DefaultSigner`. Every scheme we support signs
    /// deterministically there, so moving signing into the provider must not change a single byte.
    #[test]
    fn sign_matches_openmls_default_signer() {
        let message = b"a message which gets signed";
        for scheme in [
            SignatureScheme::ECDSA_SECP256R1_SHA256,
            SignatureScheme::ECDSA_SECP384R1_SHA384,
            SignatureScheme::ECDSA_SECP521R1_SHA512,
            SignatureScheme::ED25519,
            SignatureScheme::MLDSA44,
            SignatureScheme::MLDSA65,
            SignatureScheme::MLDSA87,
        ] {
            let mut rng = rand_chacha::ChaCha20Rng::from_seed([9; 32]);
            let (sk, pk) = super::signature_key_gen(scheme, &mut rng).unwrap();
            let expected = SignatureKeyPair::from_raw(scheme, sk.clone(), pk)
                .sign(message)
                .unwrap();
            assert_eq!(super::sign(scheme, message, &sk).unwrap(), expected, "{scheme:?}");
        }
    }
}
