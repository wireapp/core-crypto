use std::sync::{Arc, LazyLock, RwLock, RwLockWriteGuard};

use aes_gcm::{
    Aes128Gcm, Aes256Gcm, KeyInit,
    aead::{Aead, Payload},
};
use chacha20poly1305::ChaCha20Poly1305;
use hkdf::Hkdf;
// ML-DSA (FIPS-204). ml-dsa pulls signature 3.x, whose KeyInit collides with the
// ecdsa/signature 2.x one, hence the alias.
use ml_dsa::{
    B32, KeyInit as MlDsaKeyInit, MlDsa65, MlDsa87, MlDsaParams, Signature as MlDsaSignature, SignatureEncoding,
    SigningKey, VerifyingKey,
};
use openmls_traits::{
    crypto::OpenMlsCrypto,
    random::OpenMlsRand,
    types::{
        self, AeadType, Ciphersuite, CryptoError, ExporterSecret, HashType, HpkeAeadType, HpkeConfig, HpkeKdfType,
        HpkeKemType, SignatureScheme,
    },
};
use rand_core::{RngCore, SeedableRng};
use sha2::{Digest, Sha256, Sha384, Sha512};
use signature::digest::typenum::Unsigned;
use tls_codec::SecretVLBytes;

use super::{EntropySeed, Error};

/// Singleton for `RustCrypto`
/// Because of the reseed feature we have to use this
pub(crate) static CRYPTO: LazyLock<Arc<RustCrypto>> = LazyLock::new(|| Arc::new(RustCrypto::default()));

/// The type that implements
/// - key generation
/// - AEAD encryption & decryption
/// - signing & signature verification
/// - HPKE operations
#[derive(Debug, Clone)]
pub struct RustCrypto {
    pub(crate) rng: Arc<RwLock<rand_chacha::ChaCha20Rng>>,
}

impl Default for RustCrypto {
    fn default() -> Self {
        Self {
            rng: Arc::new(rand_chacha::ChaCha20Rng::from_entropy().into()),
        }
    }
}

impl RustCrypto {
    // determinism tests use this; drop the cfg-gated expect once reseeding is back
    #[cfg_attr(not(test), expect(unused))]
    pub(crate) fn new_with_seed(seed: EntropySeed) -> Self {
        Self {
            rng: Arc::new(rand_chacha::ChaCha20Rng::from_seed(seed.0).into()),
        }
    }

    pub(crate) fn reseed(&self, seed: Option<EntropySeed>) -> Result<(), Error> {
        let mut val = self.rng.write().map_err(|_| Error::RngLockPoison)?;
        *val = rand_chacha::ChaCha20Rng::from_seed(seed.unwrap_or_default().0);
        Ok(())
    }
}

/// Adapts the provider's rand_core 0.6 ChaCha20Rng to the rand_core 0.10 traits
/// hpke's *_with_rng APIs want. Without it hpke 0.14 pulls from the OS RNG, which
/// breaks new_with_seed determinism and panics on wasm.
struct HpkeRng<'a>(&'a mut rand_chacha::ChaCha20Rng);

impl hpke::rand_core::TryRng for HpkeRng<'_> {
    type Error = hpke::rand_core::Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        Ok(RngCore::next_u32(self.0))
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        Ok(RngCore::next_u64(self.0))
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
        RngCore::fill_bytes(self.0, dst);
        Ok(())
    }
}

impl hpke::rand_core::TryCryptoRng for HpkeRng<'_> {}

/// The 32-byte seed we store as the ML-DSA private key (FIPS-204 xi)
const MLDSA_SEED_LEN: usize = 32;

/// Generate an ML-DSA key pair. Returns (32-byte FIPS-204 seed, raw public key);
/// the signing key is rebuilt from the seed when signing.
fn mldsa_key_gen<P: MlDsaParams>(rng: &mut rand_chacha::ChaCha20Rng) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
    let mut seed = zeroize::Zeroizing::new(B32::default());
    rng.try_fill_bytes(&mut seed)
        .map_err(|_| CryptoError::InsufficientRandomness)?;
    let signing_key = SigningKey::<P>::from_seed(&seed);
    let public_key = signing_key.expanded_key().verifying_key().encode().to_vec();
    let private_seed = seed.to_vec();
    Ok((private_seed, public_key))
}

/// Sign data with ML-DSA parameter set P using the deterministic, empty-context
/// FIPS-204 variant required by MLS. key is the 32-byte seed produced by keygen.
fn mldsa_sign<P: MlDsaParams>(data: &[u8], key: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if key.len() != MLDSA_SEED_LEN {
        return Err(CryptoError::CryptoLibraryError);
    }
    // secret key material; scrub on drop
    let seed = zeroize::Zeroizing::new(B32::try_from(key).map_err(|_| CryptoError::CryptoLibraryError)?);
    let signing_key = SigningKey::<P>::from_seed(&seed);
    let signature = signing_key
        .expanded_key()
        .sign_deterministic(data, b"")
        .map_err(|_| CryptoError::CryptoLibraryError)?;
    Ok(signature.to_vec())
}

/// Verify a raw FIPS-204 ML-DSA signature, empty context. Fails closed: parse
/// failures and false verifications both return Err.
fn mldsa_verify<P: MlDsaParams>(data: &[u8], pk: &[u8], signature: &[u8]) -> Result<(), CryptoError> {
    let verifying_key =
        <VerifyingKey<P> as MlDsaKeyInit>::new_from_slice(pk).map_err(|_| CryptoError::CryptoLibraryError)?;
    let signature = MlDsaSignature::<P>::try_from(signature).map_err(|_| CryptoError::InvalidSignature)?;
    if verifying_key.verify_with_context(data, b"", &signature) {
        Ok(())
    } else {
        Err(CryptoError::InvalidSignature)
    }
}

/// Validate a raw FIPS-204 ML-DSA public key: it must decode as a VerifyingKey.
fn mldsa_validate_key<P: MlDsaParams>(key: &[u8]) -> Result<(), CryptoError> {
    <VerifyingKey<P> as MlDsaKeyInit>::new_from_slice(key).map_err(|_| CryptoError::InvalidKey)?;
    Ok(())
}

impl OpenMlsCrypto for RustCrypto {
    fn signature_public_key_len(&self, signature_scheme: SignatureScheme) -> usize {
        match signature_scheme {
            SignatureScheme::ECDSA_SECP256R1_SHA256 => {
                <p256::NistP256 as p256::elliptic_curve::Curve>::FieldBytesSize::to_usize()
            }
            SignatureScheme::ECDSA_SECP384R1_SHA384 => {
                <p384::NistP384 as p384::elliptic_curve::Curve>::FieldBytesSize::to_usize()
            }
            SignatureScheme::ECDSA_SECP521R1_SHA512 => {
                <p521::NistP521 as p521::elliptic_curve::Curve>::FieldBytesSize::to_usize()
            }
            SignatureScheme::ED25519 => ed25519_dalek::PUBLIC_KEY_LENGTH,
            SignatureScheme::ED448 => 57,
            // raw FIPS-204 public-key sizes
            SignatureScheme::MLDSA65 => 1952,
            SignatureScheme::MLDSA87 => 2592,
        }
    }

    fn supports(&self, cipher_suite: Ciphersuite) -> Result<(), CryptoError> {
        // 0xF001..0xF009 key-schedule through shake256_kdf_derive; byte layout is
        // provisional per mlswg PR #21.
        match cipher_suite {
            Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519
            | Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519
            | Ciphersuite::MLS_128_DHKEMP256_AES128GCM_SHA256_P256
            | Ciphersuite::MLS_256_DHKEMP384_AES256GCM_SHA384_P384
            | Ciphersuite::MLS_256_DHKEMP521_AES256GCM_SHA512_P521
            // Official SHAKE256 PQ suites (0xF001-0xF009)
            | Ciphersuite::MLS_128_MLKEM768X25519_AES128GCM_SHA256_Ed25519
            | Ciphersuite::MLS_128_MLKEM768X25519_AES256GCM_SHA384_Ed25519
            | Ciphersuite::MLS_128_MLKEM768P256_AES128GCM_SHA256_P256
            | Ciphersuite::MLS_128_MLKEM768P256_AES256GCM_SHA384_P256
            | Ciphersuite::MLS_192_MLKEM1024P384_AES256GCM_SHA384_P384
            | Ciphersuite::MLS_128_MLKEM768_AES256GCM_SHA384_P256
            | Ciphersuite::MLS_192_MLKEM1024_AES256GCM_SHA384_P384
            | Ciphersuite::MLS_192_MLKEM768_AES256GCM_SHA384_MLDSA65
            | Ciphersuite::MLS_256_MLKEM1024_AES256GCM_SHA384_MLDSA87 => Ok(()),
            _ => Err(CryptoError::UnsupportedCiphersuite),
        }
    }

    fn supported_ciphersuites(&self) -> Vec<Ciphersuite> {
        vec![
            Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519,
            Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519,
            Ciphersuite::MLS_128_DHKEMP256_AES128GCM_SHA256_P256,
            Ciphersuite::MLS_256_DHKEMP384_AES256GCM_SHA384_P384,
            Ciphersuite::MLS_256_DHKEMP521_AES256GCM_SHA512_P521,
            // Official SHAKE256 PQ suites (0xF001-0xF009)
            Ciphersuite::MLS_128_MLKEM768X25519_AES128GCM_SHA256_Ed25519,
            Ciphersuite::MLS_128_MLKEM768X25519_AES256GCM_SHA384_Ed25519,
            Ciphersuite::MLS_128_MLKEM768P256_AES128GCM_SHA256_P256,
            Ciphersuite::MLS_128_MLKEM768P256_AES256GCM_SHA384_P256,
            Ciphersuite::MLS_192_MLKEM1024P384_AES256GCM_SHA384_P384,
            Ciphersuite::MLS_128_MLKEM768_AES256GCM_SHA384_P256,
            Ciphersuite::MLS_192_MLKEM1024_AES256GCM_SHA384_P384,
            Ciphersuite::MLS_192_MLKEM768_AES256GCM_SHA384_MLDSA65,
            Ciphersuite::MLS_256_MLKEM1024_AES256GCM_SHA384_MLDSA87,
        ]
    }

    fn hkdf_extract(&self, hash_type: HashType, salt: &[u8], ikm: &[u8]) -> Result<SecretVLBytes, CryptoError> {
        match hash_type {
            HashType::Sha2_256 => Ok(Hkdf::<Sha256>::extract(Some(salt), ikm).0.as_slice().into()),
            HashType::Sha2_384 => Ok(Hkdf::<Sha384>::extract(Some(salt), ikm).0.as_slice().into()),
            HashType::Sha2_512 => Ok(Hkdf::<Sha512>::extract(Some(salt), ikm).0.as_slice().into()),
        }
    }

    fn hkdf_expand(
        &self,
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

    fn shake256_kdf_derive(&self, input: &[u8], out_len: usize) -> Result<SecretVLBytes, CryptoError> {
        use sha3::{
            Shake256,
            digest::{ExtendableOutput, Update, XofReader},
        };
        let mut hasher = Shake256::default();
        hasher.update(input);
        let mut reader = hasher.finalize_xof();
        let mut out = zeroize::Zeroizing::new(vec![0u8; out_len]);
        reader.read(&mut out);
        Ok(out.as_slice().into())
    }

    fn hash(&self, hash_type: HashType, data: &[u8]) -> Result<Vec<u8>, CryptoError> {
        match hash_type {
            HashType::Sha2_256 => Ok(Sha256::digest(data).as_slice().into()),
            HashType::Sha2_384 => Ok(Sha384::digest(data).as_slice().into()),
            HashType::Sha2_512 => Ok(Sha512::digest(data).as_slice().into()),
        }
    }

    fn aead_encrypt(
        &self,
        alg: AeadType,
        key: &[u8],
        data: &[u8],
        nonce: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        match alg {
            AeadType::Aes128Gcm => {
                let aes = Aes128Gcm::new_from_slice(key).map_err(|_| CryptoError::CryptoLibraryError)?;

                aes.encrypt(nonce.into(), Payload { msg: data, aad })
                    .map(|r| r.as_slice().into())
                    .map_err(|_| CryptoError::CryptoLibraryError)
            }
            AeadType::Aes256Gcm => {
                let aes = Aes256Gcm::new_from_slice(key).map_err(|_| CryptoError::CryptoLibraryError)?;

                aes.encrypt(nonce.into(), Payload { msg: data, aad })
                    .map(|r| r.as_slice().into())
                    .map_err(|_| CryptoError::CryptoLibraryError)
            }
            AeadType::ChaCha20Poly1305 => {
                let chacha_poly = ChaCha20Poly1305::new_from_slice(key).map_err(|_| CryptoError::CryptoLibraryError)?;

                chacha_poly
                    .encrypt(nonce.into(), Payload { msg: data, aad })
                    .map(|r| r.as_slice().into())
                    .map_err(|_| CryptoError::CryptoLibraryError)
            }
        }
    }

    fn aead_decrypt(
        &self,
        alg: AeadType,
        key: &[u8],
        ct_tag: &[u8],
        nonce: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        match alg {
            AeadType::Aes128Gcm => {
                let aes = Aes128Gcm::new_from_slice(key).map_err(|_| CryptoError::CryptoLibraryError)?;
                aes.decrypt(nonce.into(), Payload { msg: ct_tag, aad })
                    .map(|r| r.as_slice().into())
                    .map_err(|_| CryptoError::AeadDecryptionError)
            }
            AeadType::Aes256Gcm => {
                let aes = Aes256Gcm::new_from_slice(key).map_err(|_| CryptoError::CryptoLibraryError)?;
                aes.decrypt(nonce.into(), Payload { msg: ct_tag, aad })
                    .map(|r| r.as_slice().into())
                    .map_err(|_| CryptoError::AeadDecryptionError)
            }
            AeadType::ChaCha20Poly1305 => {
                let chacha_poly = ChaCha20Poly1305::new_from_slice(key).map_err(|_| CryptoError::CryptoLibraryError)?;
                chacha_poly
                    .decrypt(nonce.into(), Payload { msg: ct_tag, aad })
                    .map(|r| r.as_slice().into())
                    .map_err(|_| CryptoError::AeadDecryptionError)
            }
        }
    }

    /// Generate a `(secret key, public key)` pair from a signature scheme.
    fn signature_key_gen(&self, alg: SignatureScheme) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
        let mut rng = self.rng.write().map_err(|_| CryptoError::InsufficientRandomness)?;

        match alg {
            SignatureScheme::ECDSA_SECP256R1_SHA256 => {
                let sk = p256::ecdsa::SigningKey::random(&mut *rng);
                let pk = sk.verifying_key().to_sec1_bytes().to_vec();
                Ok((sk.to_bytes().to_vec(), pk))
            }
            SignatureScheme::ECDSA_SECP384R1_SHA384 => {
                let sk = p384::ecdsa::SigningKey::random(&mut *rng);
                let pk = sk.verifying_key().to_sec1_bytes().to_vec();
                Ok((sk.to_bytes().to_vec(), pk))
            }
            SignatureScheme::ECDSA_SECP521R1_SHA512 => {
                let sk = p521::ecdsa::SigningKey::random(&mut *rng);
                let pk = p521::ecdsa::VerifyingKey::from(&sk)
                    .to_encoded_point(false)
                    .to_bytes()
                    .into();
                Ok((sk.to_bytes().to_vec(), pk))
            }
            SignatureScheme::ED25519 => {
                let k = ed25519_dalek::SigningKey::generate(&mut *rng);
                let pk = k.verifying_key();
                Ok((k.to_bytes().into(), pk.to_bytes().into()))
            }
            SignatureScheme::MLDSA65 => mldsa_key_gen::<MlDsa65>(&mut rng),
            SignatureScheme::MLDSA87 => mldsa_key_gen::<MlDsa87>(&mut rng),
            _ => Err(CryptoError::UnsupportedSignatureScheme),
        }
    }

    fn validate_signature_key(&self, alg: SignatureScheme, key: &[u8]) -> Result<(), CryptoError> {
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
            SignatureScheme::MLDSA65 => mldsa_validate_key::<MlDsa65>(key)?,
            SignatureScheme::MLDSA87 => mldsa_validate_key::<MlDsa87>(key)?,
        }
        Ok(())
    }

    fn verify_signature(
        &self,
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

                let signature =
                    p521::ecdsa::Signature::from_der(signature).map_err(|_| CryptoError::InvalidSignature)?;

                k.verify(data, &signature).map_err(|_| CryptoError::InvalidSignature)
            }
            SignatureScheme::ED25519 => {
                let k = ed25519_dalek::VerifyingKey::try_from(pk).map_err(|_| CryptoError::CryptoLibraryError)?;

                let sig = ed25519_dalek::Signature::from_slice(signature).map_err(|_| CryptoError::InvalidSignature)?;

                k.verify_strict(data, &sig).map_err(|_| CryptoError::InvalidSignature)
            }
            SignatureScheme::MLDSA65 => mldsa_verify::<MlDsa65>(data, pk, signature),
            SignatureScheme::MLDSA87 => mldsa_verify::<MlDsa87>(data, pk, signature),
            _ => Err(CryptoError::UnsupportedSignatureScheme),
        }
    }

    fn sign(&self, alg: SignatureScheme, data: &[u8], key: &[u8]) -> Result<Vec<u8>, CryptoError> {
        match alg {
            SignatureScheme::MLDSA65 => mldsa_sign::<MlDsa65>(data, key),
            SignatureScheme::MLDSA87 => mldsa_sign::<MlDsa87>(data, key),
            // Classical schemes are signed via the basic-credential crate, not here.
            _ => Err(CryptoError::UnsupportedSignatureScheme),
        }
    }

    fn hpke_seal(
        &self,
        config: HpkeConfig,
        pk_r: &[u8],
        info: &[u8],
        aad: &[u8],
        ptxt: &[u8],
    ) -> Result<types::HpkeCiphertext, CryptoError> {
        // Seeded RNG into encap, so seal stays deterministic and avoids the OS RNG.
        let mut rng = self.rng.write().map_err(|_| CryptoError::InsufficientRandomness)?;
        let mut hpke_rng = HpkeRng(&mut rng);
        match config {
            HpkeConfig(HpkeKemType::DhKem25519, HpkeKdfType::HkdfSha256, HpkeAeadType::AesGcm128) => {
                hpke_core::hpke_seal::<hpke::aead::AesGcm128, hpke::kdf::HkdfSha256, hpke::kem::X25519HkdfSha256>(
                    pk_r,
                    info,
                    aad,
                    ptxt,
                    &mut hpke_rng,
                )
            }
            HpkeConfig(HpkeKemType::DhKem25519, HpkeKdfType::HkdfSha256, HpkeAeadType::ChaCha20Poly1305) => {
                hpke_core::hpke_seal::<hpke::aead::ChaCha20Poly1305, hpke::kdf::HkdfSha256, hpke::kem::X25519HkdfSha256>(
                    pk_r,
                    info,
                    aad,
                    ptxt,
                    &mut hpke_rng,
                )
            }
            HpkeConfig(HpkeKemType::DhKemP256, HpkeKdfType::HkdfSha256, HpkeAeadType::AesGcm128) => {
                hpke_core::hpke_seal::<hpke::aead::AesGcm128, hpke::kdf::HkdfSha256, hpke::kem::DhP256HkdfSha256>(
                    pk_r,
                    info,
                    aad,
                    ptxt,
                    &mut hpke_rng,
                )
            }
            HpkeConfig(HpkeKemType::DhKemP384, HpkeKdfType::HkdfSha384, HpkeAeadType::AesGcm256) => {
                hpke_core::hpke_seal::<hpke::aead::AesGcm256, hpke::kdf::HkdfSha384, hpke::kem::DhP384HkdfSha384>(
                    pk_r,
                    info,
                    aad,
                    ptxt,
                    &mut hpke_rng,
                )
            }
            HpkeConfig(HpkeKemType::DhKemP521, HpkeKdfType::HkdfSha512, HpkeAeadType::AesGcm256) => {
                hpke_core::hpke_seal::<hpke::aead::AesGcm256, hpke::kdf::HkdfSha512, hpke::kem::DhP521HkdfSha512>(
                    pk_r,
                    info,
                    aad,
                    ptxt,
                    &mut hpke_rng,
                )
            }
            // PQ arms, all KdfShake256
            HpkeConfig(HpkeKemType::MlKem768X25519, HpkeKdfType::Shake256, HpkeAeadType::AesGcm128) => {
                hpke_core::hpke_seal::<hpke::aead::AesGcm128, hpke::kdf::KdfShake256, hpke::kem::XWing>(
                    pk_r,
                    info,
                    aad,
                    ptxt,
                    &mut hpke_rng,
                )
            }
            HpkeConfig(HpkeKemType::MlKem768X25519, HpkeKdfType::Shake256, HpkeAeadType::AesGcm256) => {
                hpke_core::hpke_seal::<hpke::aead::AesGcm256, hpke::kdf::KdfShake256, hpke::kem::XWing>(
                    pk_r,
                    info,
                    aad,
                    ptxt,
                    &mut hpke_rng,
                )
            }
            HpkeConfig(HpkeKemType::MlKem768P256, HpkeKdfType::Shake256, HpkeAeadType::AesGcm128) => {
                hpke_core::hpke_seal::<hpke::aead::AesGcm128, hpke::kdf::KdfShake256, hpke::kem::MlKem768P256>(
                    pk_r,
                    info,
                    aad,
                    ptxt,
                    &mut hpke_rng,
                )
            }
            HpkeConfig(HpkeKemType::MlKem768P256, HpkeKdfType::Shake256, HpkeAeadType::AesGcm256) => {
                hpke_core::hpke_seal::<hpke::aead::AesGcm256, hpke::kdf::KdfShake256, hpke::kem::MlKem768P256>(
                    pk_r,
                    info,
                    aad,
                    ptxt,
                    &mut hpke_rng,
                )
            }
            HpkeConfig(HpkeKemType::MlKem1024P384, HpkeKdfType::Shake256, HpkeAeadType::AesGcm256) => {
                hpke_core::hpke_seal::<hpke::aead::AesGcm256, hpke::kdf::KdfShake256, hpke::kem::MlKem1024P384>(
                    pk_r,
                    info,
                    aad,
                    ptxt,
                    &mut hpke_rng,
                )
            }
            HpkeConfig(HpkeKemType::MlKem768, HpkeKdfType::Shake256, HpkeAeadType::AesGcm256) => {
                hpke_core::hpke_seal::<hpke::aead::AesGcm256, hpke::kdf::KdfShake256, hpke::kem::MlKem768>(
                    pk_r,
                    info,
                    aad,
                    ptxt,
                    &mut hpke_rng,
                )
            }
            HpkeConfig(HpkeKemType::MlKem1024, HpkeKdfType::Shake256, HpkeAeadType::AesGcm256) => {
                hpke_core::hpke_seal::<hpke::aead::AesGcm256, hpke::kdf::KdfShake256, hpke::kem::MlKem1024>(
                    pk_r,
                    info,
                    aad,
                    ptxt,
                    &mut hpke_rng,
                )
            }
            _ => Err(CryptoError::UnsupportedKem),
        }
    }

    fn hpke_open(
        &self,
        config: HpkeConfig,
        input: &types::HpkeCiphertext,
        sk_r: &[u8],
        info: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        let plaintext = match config {
            HpkeConfig(HpkeKemType::DhKem25519, HpkeKdfType::HkdfSha256, HpkeAeadType::AesGcm128) => {
                hpke_core::hpke_open::<hpke::aead::AesGcm128, hpke::kdf::HkdfSha256, hpke::kem::X25519HkdfSha256>(
                    sk_r,
                    input.kem_output.as_slice(),
                    info,
                    aad,
                    input.ciphertext.as_slice(),
                )?
            }
            HpkeConfig(HpkeKemType::DhKem25519, HpkeKdfType::HkdfSha256, HpkeAeadType::ChaCha20Poly1305) => {
                hpke_core::hpke_open::<hpke::aead::ChaCha20Poly1305, hpke::kdf::HkdfSha256, hpke::kem::X25519HkdfSha256>(
                    sk_r,
                    input.kem_output.as_slice(),
                    info,
                    aad,
                    input.ciphertext.as_slice(),
                )?
            }
            HpkeConfig(HpkeKemType::DhKemP256, HpkeKdfType::HkdfSha256, HpkeAeadType::AesGcm128) => {
                hpke_core::hpke_open::<hpke::aead::AesGcm128, hpke::kdf::HkdfSha256, hpke::kem::DhP256HkdfSha256>(
                    sk_r,
                    input.kem_output.as_slice(),
                    info,
                    aad,
                    input.ciphertext.as_slice(),
                )?
            }
            HpkeConfig(HpkeKemType::DhKemP384, HpkeKdfType::HkdfSha384, HpkeAeadType::AesGcm256) => {
                hpke_core::hpke_open::<hpke::aead::AesGcm256, hpke::kdf::HkdfSha384, hpke::kem::DhP384HkdfSha384>(
                    sk_r,
                    input.kem_output.as_slice(),
                    info,
                    aad,
                    input.ciphertext.as_slice(),
                )?
            }
            HpkeConfig(HpkeKemType::DhKemP521, HpkeKdfType::HkdfSha512, HpkeAeadType::AesGcm256) => {
                hpke_core::hpke_open::<hpke::aead::AesGcm256, hpke::kdf::HkdfSha512, hpke::kem::DhP521HkdfSha512>(
                    sk_r,
                    input.kem_output.as_slice(),
                    info,
                    aad,
                    input.ciphertext.as_slice(),
                )?
            }
            // PQ HPKE arms, all on KdfShake256
            HpkeConfig(HpkeKemType::MlKem768X25519, HpkeKdfType::Shake256, HpkeAeadType::AesGcm128) => {
                hpke_core::hpke_open::<hpke::aead::AesGcm128, hpke::kdf::KdfShake256, hpke::kem::XWing>(
                    sk_r,
                    input.kem_output.as_slice(),
                    info,
                    aad,
                    input.ciphertext.as_slice(),
                )?
            }
            HpkeConfig(HpkeKemType::MlKem768X25519, HpkeKdfType::Shake256, HpkeAeadType::AesGcm256) => {
                hpke_core::hpke_open::<hpke::aead::AesGcm256, hpke::kdf::KdfShake256, hpke::kem::XWing>(
                    sk_r,
                    input.kem_output.as_slice(),
                    info,
                    aad,
                    input.ciphertext.as_slice(),
                )?
            }
            HpkeConfig(HpkeKemType::MlKem768P256, HpkeKdfType::Shake256, HpkeAeadType::AesGcm128) => {
                hpke_core::hpke_open::<hpke::aead::AesGcm128, hpke::kdf::KdfShake256, hpke::kem::MlKem768P256>(
                    sk_r,
                    input.kem_output.as_slice(),
                    info,
                    aad,
                    input.ciphertext.as_slice(),
                )?
            }
            HpkeConfig(HpkeKemType::MlKem768P256, HpkeKdfType::Shake256, HpkeAeadType::AesGcm256) => {
                hpke_core::hpke_open::<hpke::aead::AesGcm256, hpke::kdf::KdfShake256, hpke::kem::MlKem768P256>(
                    sk_r,
                    input.kem_output.as_slice(),
                    info,
                    aad,
                    input.ciphertext.as_slice(),
                )?
            }
            HpkeConfig(HpkeKemType::MlKem1024P384, HpkeKdfType::Shake256, HpkeAeadType::AesGcm256) => {
                hpke_core::hpke_open::<hpke::aead::AesGcm256, hpke::kdf::KdfShake256, hpke::kem::MlKem1024P384>(
                    sk_r,
                    input.kem_output.as_slice(),
                    info,
                    aad,
                    input.ciphertext.as_slice(),
                )?
            }
            HpkeConfig(HpkeKemType::MlKem768, HpkeKdfType::Shake256, HpkeAeadType::AesGcm256) => {
                hpke_core::hpke_open::<hpke::aead::AesGcm256, hpke::kdf::KdfShake256, hpke::kem::MlKem768>(
                    sk_r,
                    input.kem_output.as_slice(),
                    info,
                    aad,
                    input.ciphertext.as_slice(),
                )?
            }
            HpkeConfig(HpkeKemType::MlKem1024, HpkeKdfType::Shake256, HpkeAeadType::AesGcm256) => {
                hpke_core::hpke_open::<hpke::aead::AesGcm256, hpke::kdf::KdfShake256, hpke::kem::MlKem1024>(
                    sk_r,
                    input.kem_output.as_slice(),
                    info,
                    aad,
                    input.ciphertext.as_slice(),
                )?
            }
            _ => return Err(CryptoError::UnsupportedKem),
        };

        Ok(plaintext)
    }

    fn hpke_setup_sender_and_export(
        &self,
        config: HpkeConfig,
        pk_r: &[u8],
        info: &[u8],
        exporter_context: &[u8],
        exporter_length: usize,
    ) -> Result<(Vec<u8>, ExporterSecret), CryptoError> {
        // Same seeded-RNG handling as hpke_seal.
        let mut rng = self.rng.write().map_err(|_| CryptoError::InsufficientRandomness)?;
        let mut hpke_rng = HpkeRng(&mut rng);
        let (kem_output, export) = match config {
            HpkeConfig(HpkeKemType::DhKem25519, HpkeKdfType::HkdfSha256, HpkeAeadType::AesGcm128) => {
                hpke_core::hpke_export_tx::<hpke::aead::AesGcm128, hpke::kdf::HkdfSha256, hpke::kem::X25519HkdfSha256>(
                    pk_r,
                    info,
                    exporter_context,
                    exporter_length,
                    &mut hpke_rng,
                )?
            }
            HpkeConfig(HpkeKemType::DhKem25519, HpkeKdfType::HkdfSha256, HpkeAeadType::ChaCha20Poly1305) => {
                hpke_core::hpke_export_tx::<
                    hpke::aead::ChaCha20Poly1305,
                    hpke::kdf::HkdfSha256,
                    hpke::kem::X25519HkdfSha256,
                >(pk_r, info, exporter_context, exporter_length, &mut hpke_rng)?
            }
            HpkeConfig(HpkeKemType::DhKemP256, HpkeKdfType::HkdfSha256, HpkeAeadType::AesGcm128) => {
                hpke_core::hpke_export_tx::<hpke::aead::AesGcm128, hpke::kdf::HkdfSha256, hpke::kem::DhP256HkdfSha256>(
                    pk_r,
                    info,
                    exporter_context,
                    exporter_length,
                    &mut hpke_rng,
                )?
            }
            HpkeConfig(HpkeKemType::DhKemP384, HpkeKdfType::HkdfSha384, HpkeAeadType::AesGcm256) => {
                hpke_core::hpke_export_tx::<hpke::aead::AesGcm256, hpke::kdf::HkdfSha384, hpke::kem::DhP384HkdfSha384>(
                    pk_r,
                    info,
                    exporter_context,
                    exporter_length,
                    &mut hpke_rng,
                )?
            }
            HpkeConfig(HpkeKemType::DhKemP521, HpkeKdfType::HkdfSha512, HpkeAeadType::AesGcm256) => {
                hpke_core::hpke_export_tx::<hpke::aead::AesGcm256, hpke::kdf::HkdfSha512, hpke::kem::DhP521HkdfSha512>(
                    pk_r,
                    info,
                    exporter_context,
                    exporter_length,
                    &mut hpke_rng,
                )?
            }
            // PQ arms, all KdfShake256
            HpkeConfig(HpkeKemType::MlKem768X25519, HpkeKdfType::Shake256, HpkeAeadType::AesGcm128) => {
                hpke_core::hpke_export_tx::<hpke::aead::AesGcm128, hpke::kdf::KdfShake256, hpke::kem::XWing>(
                    pk_r,
                    info,
                    exporter_context,
                    exporter_length,
                    &mut hpke_rng,
                )?
            }
            HpkeConfig(HpkeKemType::MlKem768X25519, HpkeKdfType::Shake256, HpkeAeadType::AesGcm256) => {
                hpke_core::hpke_export_tx::<hpke::aead::AesGcm256, hpke::kdf::KdfShake256, hpke::kem::XWing>(
                    pk_r,
                    info,
                    exporter_context,
                    exporter_length,
                    &mut hpke_rng,
                )?
            }
            HpkeConfig(HpkeKemType::MlKem768P256, HpkeKdfType::Shake256, HpkeAeadType::AesGcm128) => {
                hpke_core::hpke_export_tx::<hpke::aead::AesGcm128, hpke::kdf::KdfShake256, hpke::kem::MlKem768P256>(
                    pk_r,
                    info,
                    exporter_context,
                    exporter_length,
                    &mut hpke_rng,
                )?
            }
            HpkeConfig(HpkeKemType::MlKem768P256, HpkeKdfType::Shake256, HpkeAeadType::AesGcm256) => {
                hpke_core::hpke_export_tx::<hpke::aead::AesGcm256, hpke::kdf::KdfShake256, hpke::kem::MlKem768P256>(
                    pk_r,
                    info,
                    exporter_context,
                    exporter_length,
                    &mut hpke_rng,
                )?
            }
            HpkeConfig(HpkeKemType::MlKem1024P384, HpkeKdfType::Shake256, HpkeAeadType::AesGcm256) => {
                hpke_core::hpke_export_tx::<hpke::aead::AesGcm256, hpke::kdf::KdfShake256, hpke::kem::MlKem1024P384>(
                    pk_r,
                    info,
                    exporter_context,
                    exporter_length,
                    &mut hpke_rng,
                )?
            }
            HpkeConfig(HpkeKemType::MlKem768, HpkeKdfType::Shake256, HpkeAeadType::AesGcm256) => {
                hpke_core::hpke_export_tx::<hpke::aead::AesGcm256, hpke::kdf::KdfShake256, hpke::kem::MlKem768>(
                    pk_r,
                    info,
                    exporter_context,
                    exporter_length,
                    &mut hpke_rng,
                )?
            }
            HpkeConfig(HpkeKemType::MlKem1024, HpkeKdfType::Shake256, HpkeAeadType::AesGcm256) => {
                hpke_core::hpke_export_tx::<hpke::aead::AesGcm256, hpke::kdf::KdfShake256, hpke::kem::MlKem1024>(
                    pk_r,
                    info,
                    exporter_context,
                    exporter_length,
                    &mut hpke_rng,
                )?
            }
            _ => return Err(CryptoError::UnsupportedKem),
        };

        debug_assert_eq!(export.len(), exporter_length);

        Ok((kem_output, export.into()))
    }

    fn hpke_setup_receiver_and_export(
        &self,
        config: HpkeConfig,
        enc: &[u8],
        sk_r: &[u8],
        info: &[u8],
        exporter_context: &[u8],
        exporter_length: usize,
    ) -> Result<ExporterSecret, CryptoError> {
        let export = match config {
            HpkeConfig(HpkeKemType::DhKem25519, HpkeKdfType::HkdfSha256, HpkeAeadType::AesGcm128) => {
                hpke_core::hpke_export_rx::<hpke::aead::AesGcm128, hpke::kdf::HkdfSha256, hpke::kem::X25519HkdfSha256>(
                    enc,
                    sk_r,
                    info,
                    exporter_context,
                    exporter_length,
                )?
            }
            HpkeConfig(HpkeKemType::DhKem25519, HpkeKdfType::HkdfSha256, HpkeAeadType::ChaCha20Poly1305) => {
                hpke_core::hpke_export_rx::<
                    hpke::aead::ChaCha20Poly1305,
                    hpke::kdf::HkdfSha256,
                    hpke::kem::X25519HkdfSha256,
                >(enc, sk_r, info, exporter_context, exporter_length)?
            }
            HpkeConfig(HpkeKemType::DhKemP256, HpkeKdfType::HkdfSha256, HpkeAeadType::AesGcm128) => {
                hpke_core::hpke_export_rx::<hpke::aead::AesGcm128, hpke::kdf::HkdfSha256, hpke::kem::DhP256HkdfSha256>(
                    enc,
                    sk_r,
                    info,
                    exporter_context,
                    exporter_length,
                )?
            }
            HpkeConfig(HpkeKemType::DhKemP384, HpkeKdfType::HkdfSha384, HpkeAeadType::AesGcm256) => {
                hpke_core::hpke_export_rx::<hpke::aead::AesGcm256, hpke::kdf::HkdfSha384, hpke::kem::DhP384HkdfSha384>(
                    enc,
                    sk_r,
                    info,
                    exporter_context,
                    exporter_length,
                )?
            }
            HpkeConfig(HpkeKemType::DhKemP521, HpkeKdfType::HkdfSha512, HpkeAeadType::AesGcm256) => {
                hpke_core::hpke_export_rx::<hpke::aead::AesGcm256, hpke::kdf::HkdfSha512, hpke::kem::DhP521HkdfSha512>(
                    enc,
                    sk_r,
                    info,
                    exporter_context,
                    exporter_length,
                )?
            }
            // PQ HPKE arms - all use KdfShake256
            HpkeConfig(HpkeKemType::MlKem768X25519, HpkeKdfType::Shake256, HpkeAeadType::AesGcm128) => {
                hpke_core::hpke_export_rx::<hpke::aead::AesGcm128, hpke::kdf::KdfShake256, hpke::kem::XWing>(
                    enc,
                    sk_r,
                    info,
                    exporter_context,
                    exporter_length,
                )?
            }
            HpkeConfig(HpkeKemType::MlKem768X25519, HpkeKdfType::Shake256, HpkeAeadType::AesGcm256) => {
                hpke_core::hpke_export_rx::<hpke::aead::AesGcm256, hpke::kdf::KdfShake256, hpke::kem::XWing>(
                    enc,
                    sk_r,
                    info,
                    exporter_context,
                    exporter_length,
                )?
            }
            HpkeConfig(HpkeKemType::MlKem768P256, HpkeKdfType::Shake256, HpkeAeadType::AesGcm128) => {
                hpke_core::hpke_export_rx::<hpke::aead::AesGcm128, hpke::kdf::KdfShake256, hpke::kem::MlKem768P256>(
                    enc,
                    sk_r,
                    info,
                    exporter_context,
                    exporter_length,
                )?
            }
            HpkeConfig(HpkeKemType::MlKem768P256, HpkeKdfType::Shake256, HpkeAeadType::AesGcm256) => {
                hpke_core::hpke_export_rx::<hpke::aead::AesGcm256, hpke::kdf::KdfShake256, hpke::kem::MlKem768P256>(
                    enc,
                    sk_r,
                    info,
                    exporter_context,
                    exporter_length,
                )?
            }
            HpkeConfig(HpkeKemType::MlKem1024P384, HpkeKdfType::Shake256, HpkeAeadType::AesGcm256) => {
                hpke_core::hpke_export_rx::<hpke::aead::AesGcm256, hpke::kdf::KdfShake256, hpke::kem::MlKem1024P384>(
                    enc,
                    sk_r,
                    info,
                    exporter_context,
                    exporter_length,
                )?
            }
            HpkeConfig(HpkeKemType::MlKem768, HpkeKdfType::Shake256, HpkeAeadType::AesGcm256) => {
                hpke_core::hpke_export_rx::<hpke::aead::AesGcm256, hpke::kdf::KdfShake256, hpke::kem::MlKem768>(
                    enc,
                    sk_r,
                    info,
                    exporter_context,
                    exporter_length,
                )?
            }
            HpkeConfig(HpkeKemType::MlKem1024, HpkeKdfType::Shake256, HpkeAeadType::AesGcm256) => {
                hpke_core::hpke_export_rx::<hpke::aead::AesGcm256, hpke::kdf::KdfShake256, hpke::kem::MlKem1024>(
                    enc,
                    sk_r,
                    info,
                    exporter_context,
                    exporter_length,
                )?
            }
            _ => return Err(CryptoError::UnsupportedKem),
        };

        debug_assert_eq!(export.len(), exporter_length);

        Ok(export.into())
    }

    fn derive_hpke_keypair(&self, config: HpkeConfig, ikm: &[u8]) -> Result<types::HpkeKeyPair, CryptoError> {
        match config.0 {
            HpkeKemType::DhKemP256 => hpke_core::hpke_derive_keypair::<hpke::kem::DhP256HkdfSha256>(ikm),
            HpkeKemType::DhKemP384 => hpke_core::hpke_derive_keypair::<hpke::kem::DhP384HkdfSha384>(ikm),
            HpkeKemType::DhKemP521 => hpke_core::hpke_derive_keypair::<hpke::kem::DhP521HkdfSha512>(ikm),
            HpkeKemType::DhKem25519 => hpke_core::hpke_derive_keypair::<hpke::kem::X25519HkdfSha256>(ikm),
            // PQ KEM keypair derivation
            HpkeKemType::MlKem768X25519 => hpke_core::hpke_derive_keypair::<hpke::kem::XWing>(ikm),
            HpkeKemType::MlKem768P256 => hpke_core::hpke_derive_keypair::<hpke::kem::MlKem768P256>(ikm),
            HpkeKemType::MlKem1024P384 => hpke_core::hpke_derive_keypair::<hpke::kem::MlKem1024P384>(ikm),
            HpkeKemType::MlKem768 => hpke_core::hpke_derive_keypair::<hpke::kem::MlKem768>(ikm),
            HpkeKemType::MlKem1024 => hpke_core::hpke_derive_keypair::<hpke::kem::MlKem1024>(ikm),
            _ => Err(CryptoError::UnsupportedKem),
        }
    }
}

mod hpke_core {
    use openmls_traits::types::{CryptoError, HpkeCiphertext, HpkeKeyPair};

    pub(crate) fn hpke_open<Aead: hpke::aead::Aead, Kdf: hpke::kdf::Kdf, Kem: hpke::Kem>(
        private_key: &[u8],
        kem_output: &[u8],
        info: &[u8],
        aad: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        use hpke::{Deserializable as _, Serializable as _};
        let encapped_key = Kem::EncappedKey::from_bytes(kem_output).map_err(|_| CryptoError::HpkeDecryptionError)?;
        // Systematically normalize private keys
        let sk_len = Kem::PrivateKey::size();
        let mut sk_buf = zeroize::Zeroizing::new(Vec::with_capacity(sk_len));
        if private_key.len() < sk_len {
            for _ in 0..(sk_len - private_key.len()) {
                sk_buf.push(0x00);
            }
        }
        sk_buf.extend_from_slice(private_key);
        let key = Kem::PrivateKey::from_bytes(&sk_buf).map_err(|_| CryptoError::HpkeDecryptionError)?;
        let plaintext =
            hpke::single_shot_open::<Aead, Kdf, Kem>(&hpke::OpModeR::Base, &key, &encapped_key, info, ciphertext, aad)
                .map_err(|_| CryptoError::HpkeDecryptionError)?;

        Ok(plaintext)
    }

    pub(crate) fn hpke_seal<Aead: hpke::aead::Aead, Kdf: hpke::kdf::Kdf, Kem: hpke::Kem>(
        public_key: &[u8],
        info: &[u8],
        aad: &[u8],
        plaintext: &[u8],
        csprng: &mut impl hpke::rand_core::CryptoRng,
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

    #[allow(dead_code)]
    pub(crate) fn hpke_gen_keypair<Kem: hpke::Kem>(
        csprng: &mut impl hpke::rand_core::CryptoRng,
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
        csprng: &mut impl hpke::rand_core::CryptoRng,
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

impl OpenMlsRand for RustCrypto {
    type Error = Error;

    type RandImpl = rand_chacha::ChaCha20Rng;
    type BorrowTarget<'a> = RwLockWriteGuard<'a, Self::RandImpl>;

    fn borrow_rand(&self) -> Result<Self::BorrowTarget<'_>, Self::Error> {
        self.rng.write().map_err(|_| Error::RngLockPoison)
    }

    fn random_array<const N: usize>(&self) -> Result<[u8; N], Self::Error> {
        let mut rng = self.borrow_rand()?;
        let mut out = [0u8; N];
        rng.try_fill_bytes(&mut out).map_err(|_| Error::UnsufficientEntropy)?;
        Ok(out)
    }

    fn random_vec(&self, len: usize) -> Result<Vec<u8>, Self::Error> {
        let mut rng = self.borrow_rand()?;
        let mut out = vec![0u8; len];
        rng.try_fill_bytes(&mut out).map_err(|_| Error::UnsufficientEntropy)?;
        Ok(out)
    }
}

// Wiring only: scheme dispatch, key lengths, malformed-key rejection.
// FIPS-204 conformance is the ml-dsa crate's job.
#[cfg(test)]
mod mldsa_tests {
    use openmls_traits::crypto::OpenMlsCrypto;

    use super::*;

    // (scheme, public key length, signature length) for the two ML-DSA variants
    const MLDSA65: (SignatureScheme, usize, usize) = (SignatureScheme::MLDSA65, 1952, 3309);
    const MLDSA87: (SignatureScheme, usize, usize) = (SignatureScheme::MLDSA87, 2592, 4627);

    #[test]
    fn signature_public_key_len_matches_fips204() {
        let provider = RustCrypto::default();
        assert_eq!(provider.signature_public_key_len(MLDSA65.0), MLDSA65.1);
        assert_eq!(provider.signature_public_key_len(MLDSA87.0), MLDSA87.1);
    }

    #[test]
    fn keygen_sign_verify_round_trip() {
        for (scheme, pk_len, sig_len) in [MLDSA65, MLDSA87] {
            let provider = RustCrypto::default();
            let (private_key, public_key) = provider
                .signature_key_gen(scheme)
                .expect("key generation should succeed");

            assert_eq!(public_key.len(), pk_len, "public key length for {scheme:?}");

            let message = b"the quick brown fox jumps over the lazy dog";
            let signature = provider
                .sign(scheme, message, &private_key)
                .expect("signing should succeed");

            assert_eq!(signature.len(), sig_len, "signature length for {scheme:?}");

            provider
                .verify_signature(scheme, message, &public_key, &signature)
                .expect("verification of a valid signature should succeed");
        }
    }

    #[test]
    fn validate_signature_key_accepts_valid_and_rejects_invalid() {
        for (scheme, pk_len, _) in [MLDSA65, MLDSA87] {
            let provider = RustCrypto::default();
            let (_, public_key) = provider.signature_key_gen(scheme).unwrap();

            provider
                .validate_signature_key(scheme, &public_key)
                .expect("a freshly generated public key must validate");

            let too_short = vec![0u8; pk_len - 1];
            assert!(
                provider.validate_signature_key(scheme, &too_short).is_err(),
                "an undersized key must be rejected for {scheme:?}"
            );
        }
    }

    /// MLS wants the deterministic empty-context variant, so signing twice must match.
    #[test]
    fn signing_is_deterministic() {
        for (scheme, ..) in [MLDSA65, MLDSA87] {
            let provider = RustCrypto::default();
            let (private_key, _) = provider.signature_key_gen(scheme).unwrap();
            let message = b"deterministic";
            let sig_a = provider.sign(scheme, message, &private_key).unwrap();
            let sig_b = provider.sign(scheme, message, &private_key).unwrap();
            assert_eq!(sig_a, sig_b, "signatures must be deterministic for {scheme:?}");
        }
    }
}

// Wiring only: that each PQ HpkeConfig maps to the right KEM/KDF/AEAD. Keypair
// sizes are pinned, which is what catches a wrong generic parameter.
#[cfg(test)]
mod pq_hpke_tests {
    use openmls_traits::{
        crypto::OpenMlsCrypto,
        types::{HpkeAeadType, HpkeConfig, HpkeKdfType, HpkeKemType},
    };

    use super::*;

    // All 7 PQ HpkeConfigs that must be wired (stored as tuples since
    // HpkeConfig doesn't derive Copy/Clone; each field type is Copy)
    fn pq_configs() -> Vec<(HpkeKemType, HpkeKdfType, HpkeAeadType)> {
        vec![
            (
                HpkeKemType::MlKem768X25519,
                HpkeKdfType::Shake256,
                HpkeAeadType::AesGcm128,
            ),
            (
                HpkeKemType::MlKem768X25519,
                HpkeKdfType::Shake256,
                HpkeAeadType::AesGcm256,
            ),
            (
                HpkeKemType::MlKem768P256,
                HpkeKdfType::Shake256,
                HpkeAeadType::AesGcm128,
            ),
            (
                HpkeKemType::MlKem768P256,
                HpkeKdfType::Shake256,
                HpkeAeadType::AesGcm256,
            ),
            (
                HpkeKemType::MlKem1024P384,
                HpkeKdfType::Shake256,
                HpkeAeadType::AesGcm256,
            ),
            (HpkeKemType::MlKem768, HpkeKdfType::Shake256, HpkeAeadType::AesGcm256),
            (HpkeKemType::MlKem1024, HpkeKdfType::Shake256, HpkeAeadType::AesGcm256),
        ]
    }

    // Expected (private_key_len, public_key_len) for each KEM type in order matching pq_configs().
    // Source: hpke crate KEM implementations (Serializable::OutputSize):
    //   XWing:         sk=32  (U32),  pk=1216 (U1216)
    //   MlKem768P256:  sk=32  (U32),  pk=1249 (U1249)
    //   MlKem1024P384: sk=32  (U32),  pk=1665 (U1665)
    //   MlKem768:      sk=64  (U64),  pk=1184 (EncapsulationKey<MlKem768Params>::KeySize)
    //   MlKem1024:     sk=64  (U64),  pk=1568 (EncapsulationKey<MlKem1024Params>::KeySize)
    fn pq_keypair_sizes() -> Vec<(usize, usize)> {
        vec![
            (32, 1216), // XWing (MlKem768X25519) - AesGcm128
            (32, 1216), // XWing (MlKem768X25519) - AesGcm256 (same KEM)
            (32, 1249), // MlKem768P256            - AesGcm128
            (32, 1249), // MlKem768P256            - AesGcm256
            (32, 1665), // MlKem1024P384           - AesGcm256
            (64, 1184), // MlKem768                - AesGcm256
            (64, 1568), // MlKem1024               - AesGcm256
        ]
    }

    /// Derive, seal, open, and check the keypair byte lengths.
    #[test]
    fn pq_hpke_seal_open_round_trip() {
        let provider = RustCrypto::default();
        let plaintext = b"pq-hpke round-trip test";
        let info = b"test-info";
        let aad = b"test-aad";

        for ((kem, kdf, aead), (expected_sk_len, expected_pk_len)) in pq_configs().into_iter().zip(pq_keypair_sizes()) {
            // 64-byte IKM, big enough for any of the PQ KEMs
            let ikm = vec![0x42u8; 64];
            let kp = provider
                .derive_hpke_keypair(HpkeConfig(kem, kdf, aead), &ikm)
                .unwrap_or_else(|e| panic!("derive_hpke_keypair failed for ({kem:?},{kdf:?},{aead:?}): {e:?}"));

            // pin the keypair wire sizes explicitly
            assert_eq!(
                kp.private.len(),
                expected_sk_len,
                "private key length mismatch for ({kem:?},{kdf:?},{aead:?})"
            );
            assert_eq!(
                kp.public.len(),
                expected_pk_len,
                "public key length mismatch for ({kem:?},{kdf:?},{aead:?})"
            );

            let ciphertext = provider
                .hpke_seal(HpkeConfig(kem, kdf, aead), &kp.public, info, aad, plaintext)
                .unwrap_or_else(|e| panic!("hpke_seal failed for ({kem:?},{kdf:?},{aead:?}): {e:?}"));

            let recovered = provider
                .hpke_open(HpkeConfig(kem, kdf, aead), &ciphertext, &kp.private, info, aad)
                .unwrap_or_else(|e| panic!("hpke_open failed for ({kem:?},{kdf:?},{aead:?}): {e:?}"));

            assert_eq!(
                recovered, plaintext,
                "seal\u{2192}open round-trip mismatch for ({kem:?},{kdf:?},{aead:?})"
            );
        }
    }

    /// Sender and receiver must agree on the exported secret.
    #[test]
    fn pq_hpke_export_sender_receiver_agree() {
        let provider = RustCrypto::default();
        let info = b"export-info";
        let exporter_ctx = b"exporter-context";
        let export_len = 32usize;

        for (kem, kdf, aead) in pq_configs() {
            let ikm = vec![0x37u8; 64];
            let kp = provider
                .derive_hpke_keypair(HpkeConfig(kem, kdf, aead), &ikm)
                .unwrap_or_else(|e| panic!("derive_hpke_keypair failed for ({kem:?},{kdf:?},{aead:?}): {e:?}"));

            let (enc, tx_export) = provider
                .hpke_setup_sender_and_export(HpkeConfig(kem, kdf, aead), &kp.public, info, exporter_ctx, export_len)
                .unwrap_or_else(|e| {
                    panic!("hpke_setup_sender_and_export failed for ({kem:?},{kdf:?},{aead:?}): {e:?}")
                });

            let rx_export = provider
                .hpke_setup_receiver_and_export(
                    HpkeConfig(kem, kdf, aead),
                    &enc,
                    &kp.private,
                    info,
                    exporter_ctx,
                    export_len,
                )
                .unwrap_or_else(|e| {
                    panic!("hpke_setup_receiver_and_export failed for ({kem:?},{kdf:?},{aead:?}): {e:?}")
                });

            assert_eq!(
                &*tx_export, &*rx_export,
                "sender/receiver export mismatch for ({kem:?},{kdf:?},{aead:?})"
            );
        }
    }

    /// 0xF001-0xF009 must be advertised as supported.
    #[test]
    fn pq_official_suites_supported() {
        let provider = RustCrypto::default();
        let supported = provider.supported_ciphersuites();
        use openmls_traits::types::Ciphersuite;
        let pq_suites = [
            Ciphersuite::MLS_128_MLKEM768X25519_AES128GCM_SHA256_Ed25519,
            Ciphersuite::MLS_128_MLKEM768X25519_AES256GCM_SHA384_Ed25519,
            Ciphersuite::MLS_128_MLKEM768P256_AES128GCM_SHA256_P256,
            Ciphersuite::MLS_128_MLKEM768P256_AES256GCM_SHA384_P256,
            Ciphersuite::MLS_192_MLKEM1024P384_AES256GCM_SHA384_P384,
            Ciphersuite::MLS_128_MLKEM768_AES256GCM_SHA384_P256,
            Ciphersuite::MLS_192_MLKEM1024_AES256GCM_SHA384_P384,
            Ciphersuite::MLS_192_MLKEM768_AES256GCM_SHA384_MLDSA65,
            Ciphersuite::MLS_256_MLKEM1024_AES256GCM_SHA384_MLDSA87,
        ];
        for suite in pq_suites {
            assert!(
                supported.contains(&suite),
                "PQ suite {suite:?} must appear in supported_ciphersuites()"
            );
            assert!(
                provider.supports(suite).is_ok(),
                "PQ suite {suite:?} must return Ok from supports()"
            );
        }
    }

    /// Same seed in, same ciphertext out. Guards against hpke reaching for the OS
    /// RNG instead of the provider's seeded one.
    #[test]
    fn hpke_seal_is_deterministic_under_seeded_rng() {
        use crate::mls_provider::EntropySeed;

        let plaintext = b"determinism test plaintext";
        let info = b"determinism-info";
        let aad = b"determinism-aad";

        // (kem, kdf, aead, ikm-byte): one classical suite, one PQ suite
        let cases: Vec<(HpkeKemType, HpkeKdfType, HpkeAeadType, u8)> = vec![
            (
                HpkeKemType::DhKem25519,
                HpkeKdfType::HkdfSha256,
                HpkeAeadType::AesGcm128,
                0x11,
            ),
            (
                HpkeKemType::MlKem768X25519,
                HpkeKdfType::Shake256,
                HpkeAeadType::AesGcm256,
                0x22,
            ),
        ];

        for (kem, kdf, aead, ikm_byte) in cases {
            // Fixed seed for both providers => identical RNG streams
            let seed = EntropySeed::from_raw([0x5Au8; 32]);
            let provider_a = RustCrypto::new_with_seed(seed.clone());
            let provider_b = RustCrypto::new_with_seed(seed);

            // derive takes no RNG, so both providers get the same keypair
            let ikm = vec![ikm_byte; 64];
            let kp = RustCrypto::default()
                .derive_hpke_keypair(HpkeConfig(kem, kdf, aead), &ikm)
                .unwrap_or_else(|e| panic!("derive_hpke_keypair failed for ({kem:?},{kdf:?},{aead:?}): {e:?}"));

            let ct_a = provider_a
                .hpke_seal(HpkeConfig(kem, kdf, aead), &kp.public, info, aad, plaintext)
                .unwrap_or_else(|e| panic!("hpke_seal (a) failed for ({kem:?},{kdf:?},{aead:?}): {e:?}"));
            let ct_b = provider_b
                .hpke_seal(HpkeConfig(kem, kdf, aead), &kp.public, info, aad, plaintext)
                .unwrap_or_else(|e| panic!("hpke_seal (b) failed for ({kem:?},{kdf:?},{aead:?}): {e:?}"));

            assert_eq!(
                ct_a.kem_output.as_slice(),
                ct_b.kem_output.as_slice(),
                "kem_output not deterministic under identical seed for ({kem:?},{kdf:?},{aead:?})"
            );
            assert_eq!(
                ct_a.ciphertext.as_slice(),
                ct_b.ciphertext.as_slice(),
                "ciphertext not deterministic under identical seed for ({kem:?},{kdf:?},{aead:?})"
            );

            // Sanity: the sealed message still opens correctly
            let recovered = provider_a
                .hpke_open(HpkeConfig(kem, kdf, aead), &ct_a, &kp.private, info, aad)
                .unwrap_or_else(|e| panic!("hpke_open failed for ({kem:?},{kdf:?},{aead:?}): {e:?}"));
            assert_eq!(
                recovered, plaintext,
                "round-trip mismatch for ({kem:?},{kdf:?},{aead:?})"
            );
        }
    }

    /// hpke_open must reject a tampered ciphertext, a tampered encapsulation and a
    /// wrong key. Pins that our wrapper propagates the error rather than swallowing it.
    #[test]
    fn pq_hpke_open_fails_closed() {
        let provider = RustCrypto::default();
        let plaintext = b"pq-hpke rejection test";
        let info = b"test-info";
        let aad = b"test-aad";

        for (kem, kdf, aead) in pq_configs() {
            let kp = provider
                .derive_hpke_keypair(HpkeConfig(kem, kdf, aead), &[0x55u8; 64])
                .unwrap_or_else(|e| panic!("derive_hpke_keypair failed for ({kem:?},{kdf:?},{aead:?}): {e:?}"));
            let sealed = provider
                .hpke_seal(HpkeConfig(kem, kdf, aead), &kp.public, info, aad, plaintext)
                .unwrap_or_else(|e| panic!("hpke_seal failed for ({kem:?},{kdf:?},{aead:?}): {e:?}"));

            // Flipping the last ciphertext byte invalidates the authentication tag
            let mut ct_bytes = sealed.ciphertext.as_slice().to_vec();
            let last = ct_bytes.len() - 1;
            ct_bytes[last] ^= 0x01;
            let flipped_ct = types::HpkeCiphertext {
                kem_output: sealed.kem_output.clone(),
                ciphertext: ct_bytes.into(),
            };
            assert!(
                provider
                    .hpke_open(HpkeConfig(kem, kdf, aead), &flipped_ct, &kp.private, info, aad)
                    .is_err(),
                "hpke_open MUST reject a flipped ciphertext for ({kem:?},{kdf:?},{aead:?})"
            );

            // A corrupted encapsulation makes decap yield the wrong shared secret
            let mut ko_bytes = sealed.kem_output.as_slice().to_vec();
            assert!(
                !ko_bytes.is_empty(),
                "kem_output is empty for ({kem:?},{kdf:?},{aead:?})"
            );
            ko_bytes[0] ^= 0xff;
            let flipped_ko = types::HpkeCiphertext {
                kem_output: ko_bytes.into(),
                ciphertext: sealed.ciphertext.clone(),
            };
            assert!(
                provider
                    .hpke_open(HpkeConfig(kem, kdf, aead), &flipped_ko, &kp.private, info, aad)
                    .is_err(),
                "hpke_open MUST reject a flipped kem_output for ({kem:?},{kdf:?},{aead:?})"
            );

            // A different keypair's private key must not open this ciphertext
            let other = provider
                .derive_hpke_keypair(HpkeConfig(kem, kdf, aead), &[0xBBu8; 64])
                .unwrap_or_else(|e| panic!("derive_hpke_keypair failed for ({kem:?},{kdf:?},{aead:?}): {e:?}"));
            assert!(
                provider
                    .hpke_open(HpkeConfig(kem, kdf, aead), &sealed, &other.private, info, aad)
                    .is_err(),
                "hpke_open MUST reject a wrong private key for ({kem:?},{kdf:?},{aead:?})"
            );
        }
    }
}

#[cfg(test)]
mod shake_kdf_tests {
    use super::*;

    #[test]
    fn shake256_kdf_derive_matches_fips202_empty_vector() {
        use openmls_traits::crypto::OpenMlsCrypto;
        let provider = RustCrypto::default();
        // FIPS-202 SHAKE256("") first 32 bytes (distinguishes SHAKE256 from SHAKE128)
        let expected = hex::decode("46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f").unwrap();
        let out = provider.shake256_kdf_derive(b"", 32).unwrap();
        assert_eq!(out.as_slice(), expected.as_slice());
        let out64 = provider.shake256_kdf_derive(b"", 64).unwrap();
        assert_eq!(&out64.as_slice()[..32], expected.as_slice());
    }
}
