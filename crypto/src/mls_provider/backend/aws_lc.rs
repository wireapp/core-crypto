//! The aws-lc-rs implementation of the primitives. Where aws-lc-rs has nothing to offer (ML-DSA, a
//! scheme we do not support at all), we delegate to the [`rustcrypto`] backend, so its behavior
//! for those cases is by construction identical.
//!
//! Every function here returns the same byte encodings as its [`rustcrypto`] counterpart.

use aws_lc_rs::{
    aead::{self, Aad, LessSafeKey, Nonce, UnboundKey},
    agreement, digest, hmac,
    signature::{self, EcdsaKeyPair, Ed25519KeyPair, KeyPair as _, ParsedPublicKey},
};
use openmls_traits::types::{
    AeadType, CryptoError, HashType, HpkeCiphertext, HpkeConfig, HpkeKeyPair, SignatureScheme,
};
use rand::Rng as _;
use tls_codec::SecretVLBytes;
use zeroize::Zeroizing;

use super::{
    hpke::{self, Dhkem, HpkePrimitives, Psk, Suite},
    rustcrypto,
};

pub(crate) fn hash(hash_type: HashType, data: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let algorithm = match hash_type {
        HashType::Sha2_256 => &digest::SHA256,
        HashType::Sha2_384 => &digest::SHA384,
        HashType::Sha2_512 => &digest::SHA512,
    };
    Ok(digest::digest(algorithm, data).as_ref().to_vec())
}

/// The key for `alg`. A key of the wrong length is a `CryptoLibraryError`, as in rustcrypto.
fn aead_key(alg: AeadType, key: &[u8]) -> Result<LessSafeKey, CryptoError> {
    let algorithm = match alg {
        AeadType::Aes128Gcm => &aead::AES_128_GCM,
        AeadType::Aes256Gcm => &aead::AES_256_GCM,
        AeadType::ChaCha20Poly1305 => &aead::CHACHA20_POLY1305,
    };
    UnboundKey::new(algorithm, key)
        .map(LessSafeKey::new)
        .map_err(|_| CryptoError::CryptoLibraryError)
}

// As in rustcrypto, the nonce length is checked before the key; both use the 16-byte tag
// appended to the ciphertext that openmls expects.
pub(crate) fn aead_encrypt(
    alg: AeadType,
    key: &[u8],
    data: &[u8],
    nonce: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let nonce = Nonce::try_assume_unique_for_key(nonce).map_err(|_| CryptoError::InvalidLength)?;
    let key = aead_key(alg, key)?;
    let mut buf = data.to_vec();
    key.seal_in_place_append_tag(nonce, Aad::from(aad), &mut buf)
        .map_err(|_| CryptoError::CryptoLibraryError)?;
    Ok(buf)
}

pub(crate) fn aead_decrypt(
    alg: AeadType,
    key: &[u8],
    ct_tag: &[u8],
    nonce: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let nonce = Nonce::try_assume_unique_for_key(nonce).map_err(|_| CryptoError::InvalidLength)?;
    let key = aead_key(alg, key)?;
    let mut buf = ct_tag.to_vec();
    let len = key
        .open_in_place(nonce, Aad::from(aad), &mut buf)
        .map_err(|_| CryptoError::AeadDecryptionError)?
        .len();
    buf.truncate(len);
    Ok(buf)
}

/// The aws-lc algorithms for an ECDSA scheme: key agreement (for deriving a public key from a
/// scalar), signing, and verification, plus the scalar length.
fn ecdsa_algorithms(
    alg: SignatureScheme,
) -> Option<(
    &'static agreement::Algorithm,
    &'static signature::EcdsaSigningAlgorithm,
    &'static signature::EcdsaVerificationAlgorithm,
    usize,
)> {
    match alg {
        SignatureScheme::ECDSA_SECP256R1_SHA256 => Some((
            &agreement::ECDH_P256,
            &signature::ECDSA_P256_SHA256_ASN1_SIGNING,
            &signature::ECDSA_P256_SHA256_ASN1,
            32,
        )),
        SignatureScheme::ECDSA_SECP384R1_SHA384 => Some((
            &agreement::ECDH_P384,
            &signature::ECDSA_P384_SHA384_ASN1_SIGNING,
            &signature::ECDSA_P384_SHA384_ASN1,
            48,
        )),
        SignatureScheme::ECDSA_SECP521R1_SHA512 => Some((
            &agreement::ECDH_P521,
            &signature::ECDSA_P521_SHA512_ASN1_SIGNING,
            &signature::ECDSA_P521_SHA512_ASN1,
            66,
        )),
        _ => None,
    }
}

/// Generate a `(secret key, public key)` pair from a signature scheme.
///
/// We draw the key material from `rng` so that the entropy source remains under our control, and
/// return the same byte encodings as the rustcrypto backend: a raw scalar for the ECDSA private
/// key, X9.62 uncompressed for the ECDSA public key, and the raw seed and point for Ed25519.
pub(crate) fn signature_key_gen(
    alg: SignatureScheme,
    rng: &mut rand_chacha::ChaCha20Rng,
) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
    if let Some((ecdh, _, _, scalar_len)) = ecdsa_algorithms(alg) {
        // aws-lc rejects a zero or out-of-range scalar, so this is rejection sampling; see
        // `ecdh_private_key_rejects_out_of_range_scalars`. P-521's order has 521 bits, so masking
        // the top byte to its lowest bit makes a rejection unlikely.
        let mut scalar = Zeroizing::new(vec![0u8; scalar_len]);
        let sk = loop {
            rng.fill_bytes(&mut scalar);
            if alg == SignatureScheme::ECDSA_SECP521R1_SHA512 {
                scalar[0] &= 0x01;
            }
            if let Ok(sk) = agreement::PrivateKey::from_private_key(ecdh, &scalar) {
                break sk;
            }
        };
        let pk = sk.compute_public_key().map_err(|_| CryptoError::CryptoLibraryError)?;
        return Ok((scalar.to_vec(), pk.as_ref().to_vec()));
    }
    match alg {
        SignatureScheme::ED25519 => {
            // Any 32 bytes are a valid Ed25519 seed, so no rejection sampling is needed.
            let mut seed = Zeroizing::new([0u8; 32]);
            rng.fill_bytes(&mut *seed);
            let sk = Ed25519KeyPair::from_seed_unchecked(&*seed).map_err(|_| CryptoError::CryptoLibraryError)?;
            Ok((seed.to_vec(), sk.public_key().as_ref().to_vec()))
        }
        _ => rustcrypto::signature_key_gen(alg, rng),
    }
}

pub(crate) fn validate_signature_key(alg: SignatureScheme, key: &[u8]) -> Result<(), CryptoError> {
    match alg {
        SignatureScheme::ED25519 => {
            ParsedPublicKey::new(&signature::ED25519, key).map_err(|_| CryptoError::InvalidKey)?;
            Ok(())
        }
        _ => match ecdsa_algorithms(alg) {
            Some((_, _, verification, _)) => {
                ParsedPublicKey::new(verification, key).map_err(|_| CryptoError::InvalidKey)?;
                Ok(())
            }
            None => rustcrypto::validate_signature_key(alg, key),
        },
    }
}

// As in rustcrypto, a public key that does not parse is a `CryptoLibraryError`, and a signature
// that does not verify is an `InvalidSignature`.
pub(crate) fn verify_signature(
    alg: SignatureScheme,
    data: &[u8],
    pk: &[u8],
    signature: &[u8],
) -> Result<(), CryptoError> {
    let verification: &'static dyn signature::VerificationAlgorithm = match alg {
        SignatureScheme::ED25519 => &signature::ED25519,
        _ => match ecdsa_algorithms(alg) {
            Some((_, _, verification, _)) => verification,
            None => return rustcrypto::verify_signature(alg, data, pk, signature),
        },
    };
    let parsed = ParsedPublicKey::new(verification, pk).map_err(|_| CryptoError::CryptoLibraryError)?;
    // aws-lc's Ed25519 accepts a public key or `R` of small order, under which a forged signature
    // verifies for any message. rustcrypto, which the browser uses, verifies with dalek's
    // `verify_strict`, which rejects both. The backends must agree on what is valid, or members
    // of one conversation on different platforms could disagree about a message or commit.
    if alg == SignatureScheme::ED25519
        && (is_small_order_ed25519(pk) || signature.get(..32).is_some_and(is_small_order_ed25519))
    {
        return Err(CryptoError::InvalidSignature);
    }
    parsed
        .verify_sig(data, signature)
        .map_err(|_| CryptoError::InvalidSignature)
}

/// Whether `point` is an encoding of one of the eight Ed25519 points of small order.
///
/// This is libsodium's `has_small_order` list: the canonical encodings of those points, plus the
/// non-canonical encodings `p` and `p + 1` of 0 and 1. The sign bit is ignored, which covers
/// the remaining encodings. All of these are public, so the comparison need not be constant-time.
fn is_small_order_ed25519(point: &[u8]) -> bool {
    const SMALL_ORDER: [[u8; 32]; 7] = [
        // 0, order 4
        [0; 32],
        // 1, the identity
        [
            0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ],
        // order 8
        [
            0x26, 0xe8, 0x95, 0x8f, 0xc2, 0xb2, 0x27, 0xb0, 0x45, 0xc3, 0xf4, 0x89, 0xf2, 0xef, 0x98, 0xf0, 0xd5, 0xdf,
            0xac, 0x05, 0xd3, 0xc6, 0x33, 0x39, 0xb1, 0x38, 0x02, 0x88, 0x6d, 0x53, 0xfc, 0x05,
        ],
        // order 8
        [
            0xc7, 0x17, 0x6a, 0x70, 0x3d, 0x4d, 0xd8, 0x4f, 0xba, 0x3c, 0x0b, 0x76, 0x0d, 0x10, 0x67, 0x0f, 0x2a, 0x20,
            0x53, 0xfa, 0x2c, 0x39, 0xcc, 0xc6, 0x4e, 0xc7, 0xfd, 0x77, 0x92, 0xac, 0x03, 0x7a,
        ],
        // p - 1, order 2
        [
            0xec, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f,
        ],
        // p, a non-canonical 0
        [
            0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f,
        ],
        // p + 1, a non-canonical 1
        [
            0xee, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f,
        ],
    ];
    let Ok(point) = <&[u8; 32]>::try_from(point) else {
        return false;
    };
    SMALL_ORDER
        .iter()
        .any(|entry| entry[..31] == point[..31] && entry[31] == point[31] & 0x7f)
}

#[cfg(test)]
pub(crate) fn is_small_order_ed25519_for_tests(point: &[u8]) -> bool {
    is_small_order_ed25519(point)
}

/// ECDSA signing with the public key in the DER, without [`sign_with_public_key`]'s fallback, so
/// tests can see whether aws-lc accepted the key.
#[cfg(test)]
pub(crate) fn ecdsa_sign_with_public_key_for_tests(
    alg: SignatureScheme,
    data: &[u8],
    key: &[u8],
    public_key: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let (_, signing, _, scalar_len) = ecdsa_algorithms(alg).expect("an ECDSA scheme");
    ecdsa_sign(signing, scalar_len, data, key, Some(public_key))
}

/// Sign `data` with the private key `key`, in the same encodings as [`rustcrypto::sign`].
///
/// One difference: aws-lc's ECDSA draws its nonce randomness itself, so unlike rustcrypto's its
/// signatures are not deterministic. Both verify the same way.
pub(crate) fn sign(alg: SignatureScheme, data: &[u8], key: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if let Some((_, signing, _, scalar_len)) = ecdsa_algorithms(alg) {
        return ecdsa_sign(signing, scalar_len, data, key, None);
    }
    match alg {
        SignatureScheme::ED25519 => {
            // As in rustcrypto, accept the legacy `seed || public key` encoding, after checking
            // that the public half belongs to the seed.
            let sk = match key.len() {
                32 => Ed25519KeyPair::from_seed_unchecked(key),
                64 => Ed25519KeyPair::from_seed_and_public_key(&key[..32], &key[32..]),
                _ => return Err(CryptoError::InvalidKey),
            }
            .map_err(|_| CryptoError::InvalidKey)?;
            Ok(sk.sign(data).as_ref().to_vec())
        }
        _ => rustcrypto::sign(alg, data, key),
    }
}

/// Like [`sign`], but with the key pair's public key, which makes ECDSA signing cheaper.
///
/// aws-lc can only load an ECDSA private key together with its public key. Given just the
/// scalar, it computes the public key, and then computes it once more to check the pair, so a
/// signature costs three scalar multiplications instead of one. Handing it the public key saves
/// one of the three. Ed25519 has nothing to gain and ignores `public_key`.
///
/// If aws-lc rejects the pair, we sign as [`sign`] does. rustcrypto never looks at the public
/// key, and a key pair whose halves don't match must not make the two backends disagree.
pub(crate) fn sign_with_public_key(
    alg: SignatureScheme,
    data: &[u8],
    key: &[u8],
    public_key: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    if let Some((_, signing, _, scalar_len)) = ecdsa_algorithms(alg)
        // Only an uncompressed point, which is what our keys hold. Checking the length also
        // bounds the size of the DER we build from it.
        && public_key.len() == 1 + 2 * scalar_len
        && let Ok(signature) = ecdsa_sign(signing, scalar_len, data, key, Some(public_key))
    {
        return Ok(signature);
    }
    sign(alg, data, key)
}

/// Sign with the ECDSA private scalar `key`, and with the matching uncompressed public key if we
/// have it.
fn ecdsa_sign(
    signing: &'static signature::EcdsaSigningAlgorithm,
    scalar_len: usize,
    data: &[u8],
    key: &[u8],
    public_key: Option<&[u8]>,
) -> Result<Vec<u8>, CryptoError> {
    if key.len() != scalar_len {
        return Err(CryptoError::InvalidKey);
    }
    let der = ec_private_key_der(key, public_key);
    let sk = EcdsaKeyPair::from_private_key_der(signing, &der).map_err(|_| CryptoError::InvalidKey)?;
    // The `rng` argument is unused by aws-lc; see above.
    let rng = aws_lc_rs::rand::SystemRandom::new();
    let signature = sk.sign(&rng, data).map_err(|_| CryptoError::CryptoLibraryError)?;
    Ok(signature.as_ref().to_vec())
}

/// The RFC 5915 `ECPrivateKey` for `scalar`: version 1, the key and, if given, the public key.
/// The optional curve parameters are left out; the caller names the curve.
fn ec_private_key_der(scalar: &[u8], public_key: Option<&[u8]>) -> Zeroizing<Vec<u8>> {
    // SEQUENCE { INTEGER 1, OCTET STRING scalar, [1] { BIT STRING public_key } }
    let mut body = Zeroizing::new(vec![0x02, 0x01, 0x01]);
    push_der(&mut body, 0x04, scalar);
    if let Some(public_key) = public_key {
        // The leading zero says no bits of the last byte are unused.
        let bit_string = [&[0x00], public_key].concat();
        let mut tagged = Vec::with_capacity(bit_string.len() + 3);
        push_der(&mut tagged, 0x03, &bit_string);
        push_der(&mut body, 0xa1, &tagged);
    }
    let mut der = Zeroizing::new(Vec::with_capacity(body.len() + 3));
    push_der(&mut der, 0x30, &body);
    der
}

/// Append the DER element with tag `tag` and contents `contents` to `out`.
///
/// Lengths take at most one byte after the long-form marker, so the contents must be under 256
/// bytes. That covers the largest key we encode: a P-521 scalar with its public key has an
/// `ECPrivateKey` body of 211 bytes.
fn push_der(out: &mut Vec<u8>, tag: u8, contents: &[u8]) {
    let len = contents.len();
    debug_assert!(len < 256, "DER element of {len} bytes");
    out.push(tag);
    if len >= 0x80 {
        out.push(0x81);
    }
    out.push(len as u8);
    out.extend_from_slice(contents);
}

fn hmac_algorithm(hash_type: HashType) -> hmac::Algorithm {
    match hash_type {
        HashType::Sha2_256 => hmac::HMAC_SHA256,
        HashType::Sha2_384 => hmac::HMAC_SHA384,
        HashType::Sha2_512 => hmac::HMAC_SHA512,
    }
}

/// HKDF-Extract (RFC 5869, section 2.2), which is HMAC keyed with the salt.
///
/// An empty salt needs no special case: HMAC pads its key with zeros to the block size, so it
/// is the same as the `HashLen` zero bytes the RFC substitutes.
pub(crate) fn hkdf_extract(hash_type: HashType, salt: &[u8], ikm: &[u8]) -> Result<SecretVLBytes, CryptoError> {
    let key = hmac::Key::new(hmac_algorithm(hash_type), salt);
    Ok(hmac::sign(&key, ikm).as_ref().into())
}

/// HKDF-Expand (RFC 5869, section 2.3).
///
/// Rejects the same inputs as the `hkdf` crate does, with the same error: a PRK shorter than the
/// hash output, and more than 255 blocks of output.
///
/// This is the RFC's loop over HMAC rather than aws-lc-rs' `hkdf::Prk`, which panics on a PRK
/// longer than 64 bytes; the `hkdf` crate accepts any PRK at least as long as the hash output.
pub(crate) fn hkdf_expand(
    hash_type: HashType,
    prk: &[u8],
    info: &[u8],
    okm_len: usize,
) -> Result<SecretVLBytes, CryptoError> {
    let algorithm = hmac_algorithm(hash_type);
    let hash_len = algorithm.digest_algorithm().output_len;
    if prk.len() < hash_len || okm_len > 255 * hash_len {
        return Err(CryptoError::HkdfOutputLengthInvalid);
    }

    let key = hmac::Key::new(algorithm, prk);
    let mut okm = Zeroizing::new(Vec::with_capacity(okm_len));
    let mut previous: Option<hmac::Tag> = None;
    for counter in 1..=okm_len.div_ceil(hash_len) {
        // T(i) = HMAC(PRK, T(i-1) || info || i), with T(0) empty.
        let mut mac = hmac::Context::with_key(&key);
        if let Some(previous) = &previous {
            mac.update(previous.as_ref());
        }
        mac.update(info);
        mac.update(&[counter as u8]);
        let block = mac.sign();

        let take = (okm_len - okm.len()).min(hash_len);
        okm.extend_from_slice(&block.as_ref()[..take]);
        previous = Some(block);
    }
    Ok(std::mem::take(&mut *okm).into())
}

/// aws-lc-rs' primitives, for the HPKE core.
pub(crate) struct AwsLc;

fn ecdh_algorithm(kem: Dhkem) -> &'static agreement::Algorithm {
    match kem {
        Dhkem::X25519 => &agreement::X25519,
        Dhkem::P256 => &agreement::ECDH_P256,
        Dhkem::P384 => &agreement::ECDH_P384,
        Dhkem::P521 => &agreement::ECDH_P521,
    }
}

/// Load a private key. aws-lc demands the exact length and, for the NIST curves, a scalar in
/// `[1, n)`.
fn ecdh_private_key(kem: Dhkem, sk: &[u8]) -> Result<agreement::PrivateKey, CryptoError> {
    agreement::PrivateKey::from_private_key(ecdh_algorithm(kem), sk).map_err(|_| CryptoError::InvalidKey)
}

impl HpkePrimitives for AwsLc {
    fn hkdf_extract(hash: HashType, salt: &[u8], ikm: &[u8]) -> Result<SecretVLBytes, CryptoError> {
        hkdf_extract(hash, salt, ikm)
    }

    fn hkdf_expand(hash: HashType, prk: &[u8], info: &[u8], len: usize) -> Result<SecretVLBytes, CryptoError> {
        hkdf_expand(hash, prk, info, len)
    }

    fn aead_encrypt(alg: AeadType, key: &[u8], data: &[u8], nonce: &[u8], aad: &[u8]) -> Result<Vec<u8>, CryptoError> {
        aead_encrypt(alg, key, data, nonce, aad)
    }

    fn aead_decrypt(alg: AeadType, key: &[u8], ct: &[u8], nonce: &[u8], aad: &[u8]) -> Result<Vec<u8>, CryptoError> {
        aead_decrypt(alg, key, ct, nonce, aad)
    }

    fn dh_public_key(kem: Dhkem, sk: &[u8]) -> Result<Vec<u8>, CryptoError> {
        // For the NIST curves this is the uncompressed point, as RFC 9180 requires.
        let pk = ecdh_private_key(kem, sk)?
            .compute_public_key()
            .map_err(|_| CryptoError::CryptoLibraryError)?;
        Ok(pk.as_ref().to_vec())
    }

    fn dh(kem: Dhkem, sk: &[u8], pk: &[u8]) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
        // `agree` parses the peer's key, which checks that a NIST curve point is on the curve, as
        // the trait requires; the core has already checked it has the uncompressed length.
        let sk = ecdh_private_key(kem, sk)?;
        agreement::agree(
            &sk,
            agreement::UnparsedPublicKey::new(ecdh_algorithm(kem), pk),
            CryptoError::InvalidKey,
            |shared| Ok(Zeroizing::new(shared.to_vec())),
        )
    }
}

/// The suite aws-lc runs through the HPKE core, or `None` if `config` must go to the rustcrypto
/// backend: the post-quantum KEMs, and anything unsupported.
fn hpke_suite(config: &HpkeConfig) -> Option<Suite> {
    Suite::from_config(config)
}

pub(crate) fn hpke_seal(
    config: &HpkeConfig,
    pk_r: &[u8],
    info: &[u8],
    aad: &[u8],
    psk: Psk<'_>,
    ptxt: &[u8],
    rng: &mut rand_chacha::ChaCha20Rng,
) -> Result<HpkeCiphertext, CryptoError> {
    match hpke_suite(config) {
        Some(suite) => hpke::seal::<AwsLc>(suite, pk_r, info, aad, psk, ptxt, rng),
        None => rustcrypto::hpke_seal(config, pk_r, info, aad, psk, ptxt, rng),
    }
}

pub(crate) fn hpke_open(
    config: &HpkeConfig,
    sk_r: &[u8],
    enc: &[u8],
    info: &[u8],
    aad: &[u8],
    psk: Psk<'_>,
    ciphertext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    match hpke_suite(config) {
        Some(suite) => hpke::open::<AwsLc>(suite, sk_r, enc, info, aad, psk, ciphertext),
        None => rustcrypto::hpke_open(config, sk_r, enc, info, aad, psk, ciphertext),
    }
}

pub(crate) fn hpke_export_tx(
    config: &HpkeConfig,
    pk_r: &[u8],
    info: &[u8],
    exporter_context: &[u8],
    len: usize,
    rng: &mut rand_chacha::ChaCha20Rng,
) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
    match hpke_suite(config) {
        Some(suite) => hpke::export_tx::<AwsLc>(suite, pk_r, info, exporter_context, len, rng),
        None => rustcrypto::hpke_export_tx(config, pk_r, info, exporter_context, len, rng),
    }
}

pub(crate) fn hpke_export_rx(
    config: &HpkeConfig,
    enc: &[u8],
    sk_r: &[u8],
    info: &[u8],
    exporter_context: &[u8],
    len: usize,
) -> Result<Vec<u8>, CryptoError> {
    match hpke_suite(config) {
        Some(suite) => hpke::export_rx::<AwsLc>(suite, enc, sk_r, info, exporter_context, len),
        None => rustcrypto::hpke_export_rx(config, enc, sk_r, info, exporter_context, len),
    }
}

pub(crate) fn hpke_derive_keypair(config: &HpkeConfig, ikm: &[u8]) -> Result<HpkeKeyPair, CryptoError> {
    match hpke_suite(config) {
        Some(suite) => hpke::derive_keypair::<AwsLc>(suite, ikm),
        None => rustcrypto::hpke_derive_keypair(config, ikm),
    }
}
