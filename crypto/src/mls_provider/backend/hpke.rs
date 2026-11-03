//! HPKE (RFC 9180) built on top of a backend's primitives.
//!
//! Neither graviola nor aws-lc-rs offers an HPKE we can use, but both have everything HPKE is
//! made of: Diffie-Hellman, HKDF, and an AEAD. This module implements HPKE once, generically over
//! [`HpkePrimitives`], so that every backend runs the same protocol logic and only the primitives
//! differ.
//!
//! The scope is what openmls asks of us: the DHKEMs over X25519, P-256, P-384, and P-521, in the
//! combinations [`Suite::from_config`] lists; base and PSK modes; single-shot seal and open; and
//! the secret export. Anything else is left to the `hpke` crate, as before.
//!
//! Errors match those of the `hpke`-crate code in `crypto_provider.rs`: every failure in seal is
//! `HpkeEncryptionError`, every failure in open is `HpkeDecryptionError`, and so on. Callers can
//! therefore switch between the two without behaving differently.

use openmls_traits::types::{
    AeadType, CryptoError, HashType, HpkeAeadType, HpkeCiphertext, HpkeConfig, HpkeKdfType, HpkeKemType, HpkeKeyPair,
};
use rand::Rng as _;
use tls_codec::SecretVLBytes;
use zeroize::Zeroizing;

/// The primitives HPKE needs from a backend.
///
/// Keys use the encodings of RFC 9180 section 7.1.1: an X25519 key is its 32 raw bytes; a NIST
/// curve private key is the big-endian scalar, padded to `Nsk` bytes, and a public key is the
/// uncompressed point.
pub(crate) trait HpkePrimitives {
    fn hkdf_extract(hash: HashType, salt: &[u8], ikm: &[u8]) -> Result<SecretVLBytes, CryptoError>;
    fn hkdf_expand(hash: HashType, prk: &[u8], info: &[u8], len: usize) -> Result<SecretVLBytes, CryptoError>;
    fn aead_encrypt(alg: AeadType, key: &[u8], data: &[u8], nonce: &[u8], aad: &[u8]) -> Result<Vec<u8>, CryptoError>;
    fn aead_decrypt(alg: AeadType, key: &[u8], ct: &[u8], nonce: &[u8], aad: &[u8]) -> Result<Vec<u8>, CryptoError>;

    /// The public key belonging to the private key `sk`.
    ///
    /// Must fail if `sk` is not a valid private key.
    fn dh_public_key(kem: Dhkem, sk: &[u8]) -> Result<Vec<u8>, CryptoError>;

    /// The Diffie-Hellman shared secret of `sk` and `pk`: for X25519 the 32-byte output, for the
    /// NIST curves the x-coordinate of the shared point.
    ///
    /// Must fail if `sk` is not a valid private key, or `pk` not a valid public key; in particular
    /// a NIST curve point must be checked to be on the curve. The all-zero X25519 output is
    /// rejected by the caller, so the backend need not check for it.
    fn dh(kem: Dhkem, sk: &[u8], pk: &[u8]) -> Result<Zeroizing<Vec<u8>>, CryptoError>;
}

/// The DHKEMs of RFC 9180 section 7.1.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Dhkem {
    X25519,
    P256,
    P384,
    P521,
}

impl Dhkem {
    fn id(self) -> u16 {
        match self {
            Self::P256 => 0x0010,
            Self::P384 => 0x0011,
            Self::P521 => 0x0012,
            Self::X25519 => 0x0020,
        }
    }

    /// The KDF the KEM uses internally, independent of the suite's KDF.
    fn kdf(self) -> HashType {
        match self {
            Self::X25519 | Self::P256 => HashType::Sha2_256,
            Self::P384 => HashType::Sha2_384,
            Self::P521 => HashType::Sha2_512,
        }
    }

    /// `Nsecret`
    fn secret_len(self) -> usize {
        match self {
            Self::X25519 | Self::P256 => 32,
            Self::P384 => 48,
            Self::P521 => 64,
        }
    }

    /// `Nsk`
    pub(crate) fn private_key_len(self) -> usize {
        match self {
            Self::X25519 | Self::P256 => 32,
            Self::P384 => 48,
            Self::P521 => 66,
        }
    }

    /// `Npk`, which is also `Nenc`.
    pub(crate) fn public_key_len(self) -> usize {
        match self {
            Self::X25519 => 32,
            Self::P256 => 65,
            Self::P384 => 97,
            Self::P521 => 133,
        }
    }

    /// For the NIST curves, the group order and the mask `DeriveKeyPair` applies to the first byte
    /// of each candidate scalar (RFC 9180 section 7.1.3).
    fn order_and_bitmask(self) -> Option<(&'static [u8], u8)> {
        match self {
            Self::X25519 => None,
            Self::P256 => Some((&P256_ORDER, 0xff)),
            Self::P384 => Some((&P384_ORDER, 0xff)),
            Self::P521 => Some((&P521_ORDER, 0x01)),
        }
    }
}

const P256_ORDER: [u8; 32] = decode_hex("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551");
const P384_ORDER: [u8; 48] =
    decode_hex("ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973");
const P521_ORDER: [u8; 66] = decode_hex(concat!(
    "01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa",
    "51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386409",
));

/// Decode a hex constant at compile time; a malformed one fails the build.
const fn decode_hex<const N: usize>(hex: &str) -> [u8; N] {
    const fn nibble(c: u8) -> u8 {
        match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'f' => c - b'a' + 10,
            _ => panic!("not a lowercase hex digit"),
        }
    }
    let hex = hex.as_bytes();
    assert!(hex.len() == 2 * N, "wrong length");
    let mut out = [0u8; N];
    let mut i = 0;
    while i < N {
        out[i] = (nibble(hex[2 * i]) << 4) | nibble(hex[2 * i + 1]);
        i += 1;
    }
    out
}

/// An HPKE ciphersuite this module implements.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Suite {
    pub(crate) kem: Dhkem,
    kdf: HashType,
    aead: AeadType,
}

impl Suite {
    /// The suite for `config`, if it is one of those the provider has always supported through
    /// the `hpke` crate. We accept no others, so that a backend using this module does not
    /// succeed where the `hpke` crate path fails with `UnsupportedKem`.
    pub(crate) fn from_config(config: &HpkeConfig) -> Option<Self> {
        use HpkeAeadType as A;
        use HpkeKdfType as K;
        use HpkeKemType as M;
        let (kem, kdf, aead) = match (config.0, config.1, config.2) {
            (M::DhKem25519, K::HkdfSha256, A::AesGcm128) => (Dhkem::X25519, HashType::Sha2_256, AeadType::Aes128Gcm),
            (M::DhKem25519, K::HkdfSha256, A::ChaCha20Poly1305) => {
                (Dhkem::X25519, HashType::Sha2_256, AeadType::ChaCha20Poly1305)
            }
            (M::DhKemP256, K::HkdfSha256, A::AesGcm128) => (Dhkem::P256, HashType::Sha2_256, AeadType::Aes128Gcm),
            (M::DhKemP384, K::HkdfSha384, A::AesGcm256) => (Dhkem::P384, HashType::Sha2_384, AeadType::Aes256Gcm),
            (M::DhKemP521, K::HkdfSha512, A::AesGcm256) => (Dhkem::P521, HashType::Sha2_512, AeadType::Aes256Gcm),
            _ => return None,
        };
        Some(Self { kem, kdf, aead })
    }

    fn id(self) -> [u8; 10] {
        let kdf_id: u16 = match self.kdf {
            HashType::Sha2_256 => 0x0001,
            HashType::Sha2_384 => 0x0002,
            HashType::Sha2_512 => 0x0003,
        };
        let aead_id: u16 = match self.aead {
            AeadType::Aes128Gcm => 0x0001,
            AeadType::Aes256Gcm => 0x0002,
            AeadType::ChaCha20Poly1305 => 0x0003,
        };
        let mut id = *b"HPKE\0\0\0\0\0\0";
        id[4..6].copy_from_slice(&self.kem.id().to_be_bytes());
        id[6..8].copy_from_slice(&kdf_id.to_be_bytes());
        id[8..10].copy_from_slice(&aead_id.to_be_bytes());
        id
    }

    /// `Nk`
    fn key_len(self) -> usize {
        match self.aead {
            AeadType::Aes128Gcm => 16,
            AeadType::Aes256Gcm | AeadType::ChaCha20Poly1305 => 32,
        }
    }

    /// `Nh`
    fn hash_len(self) -> usize {
        hash_len(self.kdf)
    }
}

/// `Nn`, the same for every AEAD we support.
const NONCE_LEN: usize = 12;

fn hash_len(hash: HashType) -> usize {
    match hash {
        HashType::Sha2_256 => 32,
        HashType::Sha2_384 => 48,
        HashType::Sha2_512 => 64,
    }
}

/// `LabeledExtract` (RFC 9180 section 4).
fn labeled_extract<P: HpkePrimitives>(
    hash: HashType,
    suite_id: &[u8],
    salt: &[u8],
    label: &[u8],
    ikm: &[u8],
) -> Result<SecretVLBytes, CryptoError> {
    let labeled_ikm = Zeroizing::new([b"HPKE-v1", suite_id, label, ikm].concat());
    P::hkdf_extract(hash, salt, &labeled_ikm)
}

/// `LabeledExpand` (RFC 9180 section 4).
fn labeled_expand<P: HpkePrimitives>(
    hash: HashType,
    suite_id: &[u8],
    prk: &[u8],
    label: &[u8],
    info: &[u8],
    len: usize,
) -> Result<SecretVLBytes, CryptoError> {
    let len_bytes = u16::try_from(len)
        .map_err(|_| CryptoError::HkdfOutputLengthInvalid)?
        .to_be_bytes();
    let labeled_info = [&len_bytes[..], b"HPKE-v1", suite_id, label, info].concat();
    P::hkdf_expand(hash, prk, &labeled_info, len)
}

fn kem_suite_id(kem: Dhkem) -> [u8; 5] {
    let mut id = *b"KEM\0\0";
    id[3..].copy_from_slice(&kem.id().to_be_bytes());
    id
}

/// `DeriveKeyPair` (RFC 9180 section 7.1.3), returning the private and public keys.
fn derive_key_pair<P: HpkePrimitives>(kem: Dhkem, ikm: &[u8]) -> Result<(SecretVLBytes, Vec<u8>), CryptoError> {
    let suite_id = kem_suite_id(kem);
    let dkp_prk = labeled_extract::<P>(kem.kdf(), &suite_id, b"", b"dkp_prk", ikm)?;
    let sk = match kem.order_and_bitmask() {
        None => {
            let sk = labeled_expand::<P>(
                kem.kdf(),
                &suite_id,
                dkp_prk.as_slice(),
                b"sk",
                b"",
                kem.private_key_len(),
            )?;
            // RFC 9180 section 7.1.2: `SerializePrivateKey` must clamp an X25519 key. The `hpke`
            // crate does, so this also keeps the stored key bytes identical across backends.
            // (The RFC's test vectors print `skRm` unclamped.)
            let mut sk = Zeroizing::new(sk.as_slice().to_vec());
            clamp_x25519(&mut sk);
            SecretVLBytes::from(sk.as_slice())
        }
        Some((order, bitmask)) => {
            let mut found = None;
            for counter in 0..=255u8 {
                let mut candidate = Zeroizing::new(
                    labeled_expand::<P>(
                        kem.kdf(),
                        &suite_id,
                        dkp_prk.as_slice(),
                        b"candidate",
                        &[counter],
                        kem.private_key_len(),
                    )?
                    .as_slice()
                    .to_vec(),
                );
                candidate[0] &= bitmask;
                if is_valid_scalar(&candidate, order) {
                    found = Some(SecretVLBytes::from(candidate.as_slice()));
                    break;
                }
            }
            // RFC 9180 calls this DeriveKeyPairError; the chance of 256 rejections is negligible.
            found.ok_or(CryptoError::CryptoLibraryError)?
        }
    };
    let pk = P::dh_public_key(kem, sk.as_slice())?;
    Ok((sk, pk))
}

/// The clamping of RFC 7748 section 5 (`decodeScalar25519`).
fn clamp_x25519(sk: &mut [u8]) {
    sk[0] &= 248;
    sk[31] &= 127;
    sk[31] |= 64;
}

/// Whether the big-endian `scalar` is in `[1, order)`. Both have the same length.
///
/// The scalar is secret, so this looks at every byte, whatever it finds.
fn is_valid_scalar(scalar: &[u8], order: &[u8]) -> bool {
    debug_assert_eq!(scalar.len(), order.len());
    // Lexicographic comparison without an early exit: `less` and `greater` become 1 at the first
    // byte that differs, and stay as they are after that.
    let (mut less, mut greater, mut nonzero) = (0u8, 0u8, 0u8);
    for (&s, &o) in scalar.iter().zip(order) {
        let undecided = !(less | greater) & 1;
        less |= undecided & u8::from(s < o);
        greater |= undecided & u8::from(s > o);
        nonzero |= s;
    }
    less == 1 && nonzero != 0
}

/// `ExtractAndExpand` from DHKEM (RFC 9180 section 4.1).
fn extract_and_expand<P: HpkePrimitives>(
    kem: Dhkem,
    dh: &[u8],
    enc: &[u8],
    pk_r: &[u8],
) -> Result<SecretVLBytes, CryptoError> {
    // A small-order X25519 point gives an all-zero output, which RFC 9180 section 7.1.4 says
    // must be rejected. The NIST curves cannot produce it: the backend validates their points.
    if kem == Dhkem::X25519 && dh.iter().fold(0, |acc, b| acc | b) == 0 {
        return Err(CryptoError::CryptoLibraryError);
    }
    let suite_id = kem_suite_id(kem);
    let kem_context = [enc, pk_r].concat();
    let eae_prk = labeled_extract::<P>(kem.kdf(), &suite_id, b"", b"eae_prk", dh)?;
    labeled_expand::<P>(
        kem.kdf(),
        &suite_id,
        eae_prk.as_slice(),
        b"shared_secret",
        &kem_context,
        kem.secret_len(),
    )
}

/// `Encap`, with the ephemeral key derived from `ikm_e`, returning `(shared_secret, enc)`.
fn encap<P: HpkePrimitives>(kem: Dhkem, pk_r: &[u8], ikm_e: &[u8]) -> Result<(SecretVLBytes, Vec<u8>), CryptoError> {
    if pk_r.len() != kem.public_key_len() {
        return Err(CryptoError::InvalidKey);
    }
    let (sk_e, pk_e) = derive_key_pair::<P>(kem, ikm_e)?;
    let dh = P::dh(kem, sk_e.as_slice(), pk_r)?;
    let shared_secret = extract_and_expand::<P>(kem, &dh, &pk_e, pk_r)?;
    Ok((shared_secret, pk_e))
}

/// `Decap`
fn decap<P: HpkePrimitives>(kem: Dhkem, enc: &[u8], sk_r: &[u8]) -> Result<SecretVLBytes, CryptoError> {
    if enc.len() != kem.public_key_len() || sk_r.len() != kem.private_key_len() {
        return Err(CryptoError::InvalidLength);
    }
    let dh = P::dh(kem, sk_r, enc)?;
    let pk_r = P::dh_public_key(kem, sk_r)?;
    extract_and_expand::<P>(kem, &dh, enc, &pk_r)
}

/// A PSK and its id, for `mode_psk`.
pub(crate) type Psk<'a> = Option<(&'a [u8], &'a [u8])>;

/// The output of the key schedule (RFC 9180 section 5.1). Single-shot APIs only ever use
/// sequence number 0, so the nonce is the base nonce.
struct Context {
    key: SecretVLBytes,
    nonce: SecretVLBytes,
    exporter_secret: SecretVLBytes,
}

fn key_schedule<P: HpkePrimitives>(
    suite: Suite,
    shared_secret: &[u8],
    info: &[u8],
    psk: Psk<'_>,
) -> Result<Context, CryptoError> {
    // `VerifyPSKInputs`: the mode follows from whether a PSK was given, and a PSK must come with
    // an id. The provider also enforces the minimum PSK length before we get here.
    let (mode, psk, psk_id) = match psk {
        None => (0u8, &[][..], &[][..]),
        Some((psk, psk_id)) if !psk.is_empty() && !psk_id.is_empty() => (1u8, psk, psk_id),
        Some(_) => return Err(CryptoError::InvalidLength),
    };
    let suite_id = suite.id();
    let psk_id_hash = labeled_extract::<P>(suite.kdf, &suite_id, b"", b"psk_id_hash", psk_id)?;
    let info_hash = labeled_extract::<P>(suite.kdf, &suite_id, b"", b"info_hash", info)?;
    let context = [&[mode][..], psk_id_hash.as_slice(), info_hash.as_slice()].concat();
    let secret = labeled_extract::<P>(suite.kdf, &suite_id, shared_secret, b"secret", psk)?;
    let expand = |label: &[u8], len| labeled_expand::<P>(suite.kdf, &suite_id, secret.as_slice(), label, &context, len);
    Ok(Context {
        key: expand(b"key", suite.key_len())?,
        nonce: expand(b"base_nonce", NONCE_LEN)?,
        exporter_secret: expand(b"exp", suite.hash_len())?,
    })
}

impl Context {
    /// `Export` (RFC 9180 section 5.3).
    fn export<P: HpkePrimitives>(
        &self,
        suite: Suite,
        exporter_context: &[u8],
        len: usize,
    ) -> Result<Vec<u8>, CryptoError> {
        if len > 255 * suite.hash_len() {
            return Err(CryptoError::ExporterError);
        }
        let secret = labeled_expand::<P>(
            suite.kdf,
            &suite.id(),
            self.exporter_secret.as_slice(),
            b"sec",
            exporter_context,
            len,
        )
        .map_err(|_| CryptoError::ExporterError)?;
        Ok(secret.as_slice().to_vec())
    }
}

/// Fresh input keying material for an ephemeral key. RFC 9180 section 7.1.3 allows generating a
/// key pair as `DeriveKeyPair` over `Nsk` random bytes.
fn ephemeral_ikm(kem: Dhkem, rng: &mut rand_chacha::ChaCha20Rng) -> Zeroizing<Vec<u8>> {
    let mut ikm = Zeroizing::new(vec![0u8; kem.private_key_len()]);
    rng.fill_bytes(&mut ikm);
    ikm
}

/// Single-shot seal, in base mode or, given a PSK, PSK mode.
pub(crate) fn seal<P: HpkePrimitives>(
    suite: Suite,
    pk_r: &[u8],
    info: &[u8],
    aad: &[u8],
    psk: Psk<'_>,
    plaintext: &[u8],
    rng: &mut rand_chacha::ChaCha20Rng,
) -> Result<HpkeCiphertext, CryptoError> {
    seal_with_ikm::<P>(suite, pk_r, info, aad, psk, plaintext, &ephemeral_ikm(suite.kem, rng))
}

fn seal_with_ikm<P: HpkePrimitives>(
    suite: Suite,
    pk_r: &[u8],
    info: &[u8],
    aad: &[u8],
    psk: Psk<'_>,
    plaintext: &[u8],
    ikm_e: &[u8],
) -> Result<HpkeCiphertext, CryptoError> {
    let inner = || {
        let (shared_secret, enc) = encap::<P>(suite.kem, pk_r, ikm_e)?;
        let ctx = key_schedule::<P>(suite, shared_secret.as_slice(), info, psk)?;
        let ciphertext = P::aead_encrypt(suite.aead, ctx.key.as_slice(), plaintext, ctx.nonce.as_slice(), aad)?;
        Ok::<_, CryptoError>(HpkeCiphertext {
            kem_output: enc.into(),
            ciphertext: ciphertext.into(),
        })
    };
    inner().map_err(|_| CryptoError::HpkeEncryptionError)
}

/// Single-shot open, in base mode or, given a PSK, PSK mode.
pub(crate) fn open<P: HpkePrimitives>(
    suite: Suite,
    sk_r: &[u8],
    enc: &[u8],
    info: &[u8],
    aad: &[u8],
    psk: Psk<'_>,
    ciphertext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let inner = || {
        let shared_secret = decap::<P>(suite.kem, enc, sk_r)?;
        let ctx = key_schedule::<P>(suite, shared_secret.as_slice(), info, psk)?;
        P::aead_decrypt(suite.aead, ctx.key.as_slice(), ciphertext, ctx.nonce.as_slice(), aad)
    };
    inner().map_err(|_| CryptoError::HpkeDecryptionError)
}

/// Set up a base-mode sender and export a secret, returning `(enc, secret)`.
pub(crate) fn export_tx<P: HpkePrimitives>(
    suite: Suite,
    pk_r: &[u8],
    info: &[u8],
    exporter_context: &[u8],
    len: usize,
    rng: &mut rand_chacha::ChaCha20Rng,
) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
    export_tx_with_ikm::<P>(suite, pk_r, info, exporter_context, len, &ephemeral_ikm(suite.kem, rng))
}

fn export_tx_with_ikm<P: HpkePrimitives>(
    suite: Suite,
    pk_r: &[u8],
    info: &[u8],
    exporter_context: &[u8],
    len: usize,
    ikm_e: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
    let setup = || {
        let (shared_secret, enc) = encap::<P>(suite.kem, pk_r, ikm_e)?;
        let ctx = key_schedule::<P>(suite, shared_secret.as_slice(), info, None)?;
        Ok::<_, CryptoError>((enc, ctx))
    };
    let (enc, ctx) = setup().map_err(|_| CryptoError::SenderSetupError)?;
    Ok((enc, ctx.export::<P>(suite, exporter_context, len)?))
}

/// Set up a base-mode receiver and export a secret.
pub(crate) fn export_rx<P: HpkePrimitives>(
    suite: Suite,
    enc: &[u8],
    sk_r: &[u8],
    info: &[u8],
    exporter_context: &[u8],
    len: usize,
) -> Result<Vec<u8>, CryptoError> {
    let setup = || {
        let shared_secret = decap::<P>(suite.kem, enc, sk_r)?;
        key_schedule::<P>(suite, shared_secret.as_slice(), info, None)
    };
    let ctx = setup().map_err(|_| CryptoError::ReceiverSetupError)?;
    ctx.export::<P>(suite, exporter_context, len)
}

/// `DeriveKeyPair` for the KEM of `suite`.
pub(crate) fn derive_keypair<P: HpkePrimitives>(suite: Suite, ikm: &[u8]) -> Result<HpkeKeyPair, CryptoError> {
    let (sk, pk) = derive_key_pair::<P>(suite.kem, ikm)?;
    Ok(HpkeKeyPair {
        private: sk.as_slice().into(),
        public: pk,
    })
}

#[cfg(test)]
pub(crate) mod tests {
    //! Checks the HPKE logic against RFC 9180's test vectors and against the `hpke` crate,
    //! using [`RustCryptoDh`]: primitives taken from RustCrypto crates the `hpke` crate does not
    //! share with us, so that the two implementations are independent. The tests are generic,
    //! so each backend can run them over its own primitives.

    use openmls_traits::types::{HpkeAeadType, HpkeConfig, HpkeKdfType, HpkeKemType};
    use rand_core::SeedableRng as _;

    use super::*;
    use crate::mls_provider::backend::rustcrypto;

    /// The configurations [`Suite::from_config`] accepts.
    pub(crate) fn configs() -> [HpkeConfig; 5] {
        [
            HpkeConfig(
                HpkeKemType::DhKem25519,
                HpkeKdfType::HkdfSha256,
                HpkeAeadType::AesGcm128,
            ),
            HpkeConfig(
                HpkeKemType::DhKem25519,
                HpkeKdfType::HkdfSha256,
                HpkeAeadType::ChaCha20Poly1305,
            ),
            HpkeConfig(HpkeKemType::DhKemP256, HpkeKdfType::HkdfSha256, HpkeAeadType::AesGcm128),
            HpkeConfig(HpkeKemType::DhKemP384, HpkeKdfType::HkdfSha384, HpkeAeadType::AesGcm256),
            HpkeConfig(HpkeKemType::DhKemP521, HpkeKdfType::HkdfSha512, HpkeAeadType::AesGcm256),
        ]
    }

    /// RustCrypto implementations of the primitives: the rustcrypto backend for HKDF and AEAD,
    /// and x25519-dalek and the `elliptic-curve` ECDH of p256/p384/p521 for Diffie-Hellman.
    pub(crate) struct RustCryptoDh;

    macro_rules! nist_dh {
        ($curve:ident, $sk:expr, $pk:expr) => {{
            let sk = $curve::SecretKey::from_slice($sk).map_err(|_| CryptoError::InvalidKey)?;
            let pk = $curve::PublicKey::from_sec1_bytes($pk).map_err(|_| CryptoError::InvalidKey)?;
            let shared = $curve::ecdh::diffie_hellman(sk.to_nonzero_scalar(), pk.as_affine());
            Ok(Zeroizing::new(shared.raw_secret_bytes().to_vec()))
        }};
    }

    macro_rules! nist_public_key {
        ($curve:ident, $sk:expr) => {{
            let sk = $curve::SecretKey::from_slice($sk).map_err(|_| CryptoError::InvalidKey)?;
            Ok(
                $curve::elliptic_curve::sec1::ToSec1Point::to_sec1_point(&sk.public_key(), false)
                    .as_bytes()
                    .to_vec(),
            )
        }};
    }

    impl HpkePrimitives for RustCryptoDh {
        fn hkdf_extract(hash: HashType, salt: &[u8], ikm: &[u8]) -> Result<SecretVLBytes, CryptoError> {
            rustcrypto::hkdf_extract(hash, salt, ikm)
        }
        fn hkdf_expand(hash: HashType, prk: &[u8], info: &[u8], len: usize) -> Result<SecretVLBytes, CryptoError> {
            rustcrypto::hkdf_expand(hash, prk, info, len)
        }
        fn aead_encrypt(
            alg: AeadType,
            key: &[u8],
            data: &[u8],
            nonce: &[u8],
            aad: &[u8],
        ) -> Result<Vec<u8>, CryptoError> {
            rustcrypto::aead_encrypt(alg, key, data, nonce, aad)
        }
        fn aead_decrypt(
            alg: AeadType,
            key: &[u8],
            ct: &[u8],
            nonce: &[u8],
            aad: &[u8],
        ) -> Result<Vec<u8>, CryptoError> {
            rustcrypto::aead_decrypt(alg, key, ct, nonce, aad)
        }
        fn dh_public_key(kem: Dhkem, sk: &[u8]) -> Result<Vec<u8>, CryptoError> {
            match kem {
                Dhkem::X25519 => {
                    let sk: [u8; 32] = sk.try_into().map_err(|_| CryptoError::InvalidKey)?;
                    let sk = x25519_dalek::StaticSecret::from(sk);
                    Ok(x25519_dalek::PublicKey::from(&sk).as_bytes().to_vec())
                }
                Dhkem::P256 => nist_public_key!(p256, sk),
                Dhkem::P384 => nist_public_key!(p384, sk),
                Dhkem::P521 => nist_public_key!(p521, sk),
            }
        }
        fn dh(kem: Dhkem, sk: &[u8], pk: &[u8]) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
            match kem {
                Dhkem::X25519 => {
                    let sk: [u8; 32] = sk.try_into().map_err(|_| CryptoError::InvalidKey)?;
                    let pk: [u8; 32] = pk.try_into().map_err(|_| CryptoError::InvalidKey)?;
                    let shared = x25519_dalek::StaticSecret::from(sk).diffie_hellman(&pk.into());
                    Ok(Zeroizing::new(shared.as_bytes().to_vec()))
                }
                Dhkem::P256 => nist_dh!(p256, sk, pk),
                Dhkem::P384 => nist_dh!(p384, sk, pk),
                Dhkem::P521 => nist_dh!(p521, sk, pk),
            }
        }
    }

    struct Vector {
        mode: u8,
        kem_id: u16,
        kdf_id: u16,
        aead_id: u16,
        info: Vec<u8>,
        ikm_r: Vec<u8>,
        ikm_e: Vec<u8>,
        sk_r: Vec<u8>,
        pk_r: Vec<u8>,
        enc: Vec<u8>,
        psk: Vec<u8>,
        psk_id: Vec<u8>,
        encryptions: Vec<Encryption>,
        exports: Vec<Export>,
    }

    struct Encryption {
        aad: Vec<u8>,
        ct: Vec<u8>,
        pt: Vec<u8>,
    }

    struct Export {
        exporter_context: Vec<u8>,
        len: usize,
        exported_value: Vec<u8>,
    }

    fn load_vectors() -> Vec<Vector> {
        use serde_json::Value;
        let bytes = |v: &Value, key: &str| {
            v.get(key)
                .map_or(Vec::new(), |s| hex::decode(s.as_str().unwrap()).unwrap())
        };
        let int = |v: &Value, key: &str| v[key].as_u64().unwrap();
        let vectors: Vec<Value> = serde_json::from_str(include_str!("hpke_rfc9180_vectors.json")).unwrap();
        vectors
            .iter()
            .map(|v| Vector {
                mode: int(v, "mode") as u8,
                kem_id: int(v, "kem_id") as u16,
                kdf_id: int(v, "kdf_id") as u16,
                aead_id: int(v, "aead_id") as u16,
                info: bytes(v, "info"),
                ikm_r: bytes(v, "ikmR"),
                ikm_e: bytes(v, "ikmE"),
                sk_r: bytes(v, "skRm"),
                pk_r: bytes(v, "pkRm"),
                enc: bytes(v, "enc"),
                psk: bytes(v, "psk"),
                psk_id: bytes(v, "psk_id"),
                encryptions: v["encryptions"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|e| Encryption {
                        aad: bytes(e, "aad"),
                        ct: bytes(e, "ct"),
                        pt: bytes(e, "pt"),
                    })
                    .collect(),
                exports: v["exports"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|e| Export {
                        exporter_context: bytes(e, "exporter_context"),
                        len: int(e, "L") as usize,
                        exported_value: bytes(e, "exported_value"),
                    })
                    .collect(),
            })
            .collect()
    }

    fn config_for(vector: &Vector) -> HpkeConfig {
        configs()
            .into_iter()
            .find(|config| {
                let suite = Suite::from_config(config).unwrap();
                let id = suite.id();
                id[4..]
                    == [
                        vector.kem_id.to_be_bytes(),
                        vector.kdf_id.to_be_bytes(),
                        vector.aead_id.to_be_bytes(),
                    ]
                    .concat()
            })
            .expect("the fixture holds only configurations we support")
    }

    /// The first encryption and every export of the RFC 9180 test vectors (appendix A) for the
    /// configurations we support, in base and PSK modes. RFC 9180 has no vectors for P-384, which
    /// [`agrees_with_the_hpke_crate`] covers.
    pub(crate) fn check_rfc9180_vectors<P: HpkePrimitives>() {
        let vectors = load_vectors();
        assert_eq!(vectors.len(), 8);
        for vector in vectors {
            let config = config_for(&vector);
            let suite = Suite::from_config(&config).unwrap();
            let context = format!("{config:?}, mode {}", vector.mode);
            let psk = (vector.mode == 1).then_some((&vector.psk[..], &vector.psk_id[..]));
            let encryption = &vector.encryptions[0];

            let keypair = derive_keypair::<P>(suite, &vector.ikm_r).unwrap();
            let mut expected_sk = vector.sk_r.clone();
            if suite.kem == Dhkem::X25519 {
                clamp_x25519(&mut expected_sk);
            }
            assert_eq!(&*keypair.private, &expected_sk[..], "{context}: derived skR");
            assert_eq!(keypair.public, vector.pk_r, "{context}: derived pkR");

            let sealed = seal_with_ikm::<P>(
                suite,
                &vector.pk_r,
                &vector.info,
                &encryption.aad,
                psk,
                &encryption.pt,
                &vector.ikm_e,
            )
            .unwrap();
            assert_eq!(sealed.kem_output.as_slice(), &vector.enc[..], "{context}: enc");
            assert_eq!(sealed.ciphertext.as_slice(), &encryption.ct[..], "{context}: ct");

            let opened = open::<P>(
                suite,
                &vector.sk_r,
                &vector.enc,
                &vector.info,
                &encryption.aad,
                psk,
                &encryption.ct,
            );
            assert_eq!(opened.as_ref(), Ok(&encryption.pt), "{context}: open");

            if vector.mode != 0 {
                continue;
            }
            for export in &vector.exports {
                let (enc, secret) = export_tx_with_ikm::<P>(
                    suite,
                    &vector.pk_r,
                    &vector.info,
                    &export.exporter_context,
                    export.len,
                    &vector.ikm_e,
                )
                .unwrap();
                assert_eq!(enc, vector.enc, "{context}: export enc");
                assert_eq!(secret, export.exported_value, "{context}: sender export");
                let secret = export_rx::<P>(
                    suite,
                    &vector.enc,
                    &vector.sk_r,
                    &vector.info,
                    &export.exporter_context,
                    export.len,
                )
                .unwrap();
                assert_eq!(secret, export.exported_value, "{context}: receiver export");
            }
        }
    }

    /// What this module produces, the `hpke` crate accepts, and the other way around. The
    /// provider's RustCrypto backend uses the `hpke` crate, so this is the contract between it and
    /// every backend using this module.
    pub(crate) fn check_agreement_with_the_hpke_crate<P: HpkePrimitives>() {
        let crypto = crate::RustCrypto::default();
        let mut rng = rand_chacha::ChaCha20Rng::from_seed([3; 32]);
        let psk = [0x77; 32];
        for config in configs() {
            let suite = Suite::from_config(&config).unwrap();
            let ikm = [0x42; 64];
            let ours = derive_keypair::<P>(suite, &ikm).unwrap();
            let theirs =
                openmls_traits::crypto::OpenMlsCrypto::derive_hpke_keypair(&crypto, config_clone(&config), &ikm)
                    .unwrap();
            assert_eq!(&*ours.private, &*theirs.private, "{config:?}: derived private key");
            assert_eq!(ours.public, theirs.public, "{config:?}: derived public key");
            let (sk, pk) = (&*ours.private, &ours.public[..]);

            for psk in [None, Some((&psk[..], &b"psk id"[..]))] {
                let context = format!("{config:?}, psk: {}", psk.is_some());
                let ours = seal::<P>(suite, pk, b"info", b"aad", psk, b"plaintext", &mut rng).unwrap();
                let theirs = hpke_crate_seal(&crypto, &config, pk, psk);

                let opened = hpke_crate_open(&crypto, &config, &ours, sk, psk);
                assert_eq!(
                    opened,
                    Ok(b"plaintext".to_vec()),
                    "{context}: the hpke crate opens ours"
                );
                let opened = open::<P>(
                    suite,
                    sk,
                    theirs.kem_output.as_slice(),
                    b"info",
                    b"aad",
                    psk,
                    theirs.ciphertext.as_slice(),
                );
                assert_eq!(opened, Ok(b"plaintext".to_vec()), "{context}: we open the hpke crate's");
            }

            let (enc, ours) = export_tx::<P>(suite, pk, b"info", b"context", 42, &mut rng).unwrap();
            let theirs = openmls_traits::crypto::OpenMlsCrypto::hpke_setup_receiver_and_export(
                &crypto,
                config_clone(&config),
                &enc,
                sk,
                b"info",
                b"context",
                42,
            )
            .unwrap();
            assert_eq!(
                ours, &*theirs,
                "{config:?}: the hpke crate's receiver exports our sender's secret"
            );
            let (enc, theirs) = openmls_traits::crypto::OpenMlsCrypto::hpke_setup_sender_and_export(
                &crypto,
                config_clone(&config),
                pk,
                b"info",
                b"context",
                42,
            )
            .unwrap();
            let ours = export_rx::<P>(suite, &enc, sk, b"info", b"context", 42).unwrap();
            assert_eq!(
                ours, &*theirs,
                "{config:?}: our receiver exports the hpke crate's sender's secret"
            );
        }
    }

    fn config_clone(config: &HpkeConfig) -> HpkeConfig {
        HpkeConfig(config.0, config.1, config.2)
    }

    fn hpke_crate_seal(crypto: &crate::RustCrypto, config: &HpkeConfig, pk: &[u8], psk: Psk<'_>) -> HpkeCiphertext {
        match psk {
            None => openmls_traits::crypto::OpenMlsCrypto::hpke_seal(
                crypto,
                config_clone(config),
                pk,
                b"info",
                b"aad",
                b"plaintext",
            ),
            Some((psk, psk_id)) => {
                crypto.hpke_seal_psk(config_clone(config), pk, b"info", b"aad", psk, psk_id, b"plaintext")
            }
        }
        .unwrap()
    }

    fn hpke_crate_open(
        crypto: &crate::RustCrypto,
        config: &HpkeConfig,
        ciphertext: &HpkeCiphertext,
        sk: &[u8],
        psk: Psk<'_>,
    ) -> Result<Vec<u8>, CryptoError> {
        match psk {
            None => openmls_traits::crypto::OpenMlsCrypto::hpke_open(
                crypto,
                config_clone(config),
                ciphertext,
                sk,
                b"info",
                b"aad",
            ),
            Some((psk, psk_id)) => {
                crypto.hpke_open_psk(config_clone(config), ciphertext, sk, b"info", b"aad", psk, psk_id)
            }
        }
    }

    /// `(description, sk, enc, ciphertext, aad, psk)`
    type OpenCase<'a> = (&'a str, &'a [u8], &'a [u8], &'a [u8], &'a [u8], Psk<'a>);

    /// Malformed input fails, with the error the `hpke`-crate path reports for it.
    pub(crate) fn check_rejections<P: HpkePrimitives>() {
        let mut rng = rand_chacha::ChaCha20Rng::from_seed([4; 32]);
        for config in configs() {
            let suite = Suite::from_config(&config).unwrap();
            let keypair = derive_keypair::<P>(suite, &[0x24; 64]).unwrap();
            let (sk, pk) = (&*keypair.private, &keypair.public[..]);
            let sealed = seal::<P>(suite, pk, b"info", b"aad", None, b"plaintext", &mut rng).unwrap();
            let (enc, ct) = (sealed.kem_output.as_slice(), sealed.ciphertext.as_slice());

            let mut tampered_ct = ct.to_vec();
            tampered_ct[0] ^= 1;
            let mut tampered_enc = enc.to_vec();
            *tampered_enc.last_mut().unwrap() ^= 1;
            let other = derive_keypair::<P>(suite, &[0x25; 64]).unwrap();

            let open_cases: [OpenCase<'_>; 7] = [
                ("tampered ciphertext", sk, enc, &tampered_ct, b"aad", None),
                ("wrong aad", sk, enc, ct, b"other aad", None),
                ("wrong key", &other.private, enc, ct, b"aad", None),
                ("tampered enc", sk, &tampered_enc, ct, b"aad", None),
                ("truncated enc", sk, &enc[..enc.len() - 1], ct, b"aad", None),
                ("truncated key", &sk[..sk.len() - 1], enc, ct, b"aad", None),
                ("unexpected psk", sk, enc, ct, b"aad", Some((&[0x77; 32], b"id"))),
            ];
            for (case, sk, enc, ct, aad, psk) in open_cases {
                assert_eq!(
                    open::<P>(suite, sk, enc, b"info", aad, psk, ct),
                    Err(CryptoError::HpkeDecryptionError),
                    "{config:?}: open, {case}"
                );
            }

            for (case, pk) in [("truncated key", &pk[..pk.len() - 1]), ("empty key", &[][..])] {
                assert_eq!(
                    seal::<P>(suite, pk, b"info", b"aad", None, b"plaintext", &mut rng),
                    Err(CryptoError::HpkeEncryptionError),
                    "{config:?}: seal, {case}"
                );
                assert!(
                    matches!(
                        export_tx::<P>(suite, pk, b"info", b"context", 32, &mut rng),
                        Err(CryptoError::SenderSetupError)
                    ),
                    "{config:?}: export_tx, {case}"
                );
            }
            assert_eq!(
                export_rx::<P>(suite, &enc[..enc.len() - 1], sk, b"info", b"context", 32),
                Err(CryptoError::ReceiverSetupError),
                "{config:?}: export_rx, truncated enc"
            );
            let too_long = 255 * suite.hash_len() + 1;
            assert_eq!(
                export_rx::<P>(suite, enc, sk, b"info", b"context", too_long),
                Err(CryptoError::ExporterError),
                "{config:?}: export_rx, too long"
            );
        }
    }

    #[test]
    fn matches_rfc9180_vectors() {
        check_rfc9180_vectors::<RustCryptoDh>();
    }

    #[test]
    fn agrees_with_the_hpke_crate() {
        check_agreement_with_the_hpke_crate::<RustCryptoDh>();
    }

    #[test]
    fn rejects_malformed_input() {
        check_rejections::<RustCryptoDh>();
    }

    /// The all-zero X25519 public key is of small order, so the shared secret is zero.
    #[test]
    fn rejects_the_all_zero_x25519_shared_secret() {
        let suite = Suite::from_config(&configs()[0]).unwrap();
        let mut rng = rand_chacha::ChaCha20Rng::from_seed([5; 32]);
        assert_eq!(
            seal::<RustCryptoDh>(suite, &[0; 32], b"info", b"aad", None, b"plaintext", &mut rng),
            Err(CryptoError::HpkeEncryptionError)
        );
    }

    #[test]
    fn scalar_range_check() {
        let order = [0x10, 0x00];
        for (scalar, valid) in [
            ([0x00, 0x00], false),
            ([0x00, 0x01], true),
            ([0x0f, 0xff], true),
            ([0x10, 0x00], false),
            ([0x10, 0x01], false),
            ([0xff, 0xff], false),
        ] {
            assert_eq!(is_valid_scalar(&scalar, &order), valid, "{scalar:02x?}");
        }
    }

    /// The group orders are those of SEC 2; check them against the RustCrypto curve crates.
    #[test]
    fn curve_orders_are_correct() {
        use p256::elliptic_curve::Curve as _;
        assert_eq!(p256::NistP256::ORDER.to_be_bytes().as_ref(), &P256_ORDER);
        assert_eq!(p384::NistP384::ORDER.to_be_bytes().as_ref(), &P384_ORDER);
        // The P-521 order is stored in a wider integer, with leading zero bytes.
        let p521_order = p521::NistP521::ORDER.to_be_bytes();
        let (padding, order) = p521_order
            .as_ref()
            .split_at(p521_order.as_ref().len() - P521_ORDER.len());
        assert!(padding.iter().all(|&b| b == 0));
        assert_eq!(order, &P521_ORDER);
    }
}
