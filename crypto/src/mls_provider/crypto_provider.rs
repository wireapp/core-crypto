use std::sync::{Arc, LazyLock, RwLock, RwLockWriteGuard};

use aes_gcm::{
    Aes128Gcm, Aes256Gcm, KeyInit,
    aead::{Aead, Nonce, Payload},
};
use chacha20poly1305::ChaCha20Poly1305;
use elliptic_curve::Generate as _;
use hkdf::Hkdf;
use ml_dsa::{MlDsa44, MlDsa65, MlDsa87};
use openmls::prelude::HpkeCiphertext;
use openmls_traits::{
    crypto::OpenMlsCrypto,
    mldsa,
    random::OpenMlsRand,
    types::{
        self, AeadType, Ciphersuite, CryptoError, ExporterSecret, HashType, HpkeAeadType, HpkeConfig, HpkeKdfType,
        HpkeKemType, SignatureScheme,
    },
};
use rand::Rng as _;
use rand_core::SeedableRng as _;
use sha2::{Digest, Sha256, Sha384, Sha512};
use signature::digest::typenum::Unsigned;
use tls_codec::SecretVLBytes;

use super::{EntropySeed, Error, RawEntropySeed};

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
        let mut seed = RawEntropySeed::default();
        getrandom::fill(&mut seed).expect("system RNG has to work");
        Self::new_with_seed(EntropySeed::from_raw(seed))
    }
}

/// one table for every entry point
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

/// every HpkeKemType case is listed here, so a new one is a compile error as an early sign that something's missing here
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

impl RustCrypto {
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

    #[expect(clippy::too_many_arguments)]
    pub(crate) fn hpke_seal_psk(
        &self,
        config: HpkeConfig,
        pk_r: &[u8],
        info: &[u8],
        aad: &[u8],
        psk: &[u8],
        psk_id: &[u8],
        ptxt: &[u8],
    ) -> Result<HpkeCiphertext, CryptoError> {
        let mut rng = self.rng.write().map_err(|_| CryptoError::InsufficientRandomness)?;
        hpke_dispatch!(config, hpke_seal_psk, pk_r, info, aad, psk, psk_id, ptxt, &mut *rng)
    }

    #[expect(clippy::too_many_arguments)]
    pub(crate) fn hpke_open_psk(
        &self,
        config: HpkeConfig,
        input: &HpkeCiphertext,
        sk_r: &[u8],
        info: &[u8],
        aad: &[u8],
        psk: &[u8],
        psk_id: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        hpke_dispatch!(
            config,
            hpke_open_psk,
            sk_r,
            input.kem_output.as_slice(),
            info,
            aad,
            psk,
            psk_id,
            input.ciphertext.as_slice(),
        )
    }
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
            SignatureScheme::MLDSA44 => 1312,
            SignatureScheme::MLDSA65 => 1952,
            SignatureScheme::MLDSA87 => 2592,
        }
    }

    fn supports(&self, cipher_suite: Ciphersuite) -> Result<(), CryptoError> {
        match cipher_suite {
            Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519
            | Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519
            | Ciphersuite::MLS_128_DHKEMP256_AES128GCM_SHA256_P256
            | Ciphersuite::MLS_256_DHKEMP384_AES256GCM_SHA384_P384
            | Ciphersuite::MLS_256_DHKEMP521_AES256GCM_SHA512_P521
            // draft-ietf-mls-pq-ciphersuites-06, placeholder codepoints 0xF001 to 0xF00B
            | Ciphersuite::MLS_128_MLKEM768X25519_AES128GCM_SHA256_Ed25519
            | Ciphersuite::MLS_128_MLKEM768X25519_AES256GCM_SHA384_Ed25519
            | Ciphersuite::MLS_128_MLKEM768P256_AES128GCM_SHA256_P256
            | Ciphersuite::MLS_128_MLKEM768P256_AES256GCM_SHA384_P256
            | Ciphersuite::MLS_192_MLKEM1024P384_AES256GCM_SHA384_P384
            | Ciphersuite::MLS_128_MLKEM768_AES256GCM_SHA384_P256
            | Ciphersuite::MLS_192_MLKEM1024_AES256GCM_SHA384_P384
            | Ciphersuite::MLS_192_MLKEM768_AES256GCM_SHA384_MLDSA65
            | Ciphersuite::MLS_256_MLKEM1024_AES256GCM_SHA384_MLDSA87
            | Ciphersuite::MLS_128_MLKEM768_AES256GCM_SHA384_Ed25519
            | Ciphersuite::MLS_128_MLKEM768X25519_CHACHA20POLY1305_SHA384_MLDSA44 => Ok(()),
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
            // draft-ietf-mls-pq-ciphersuites-06, placeholder codepoints 0xF001 to 0xF00B
            Ciphersuite::MLS_128_MLKEM768X25519_AES128GCM_SHA256_Ed25519,
            Ciphersuite::MLS_128_MLKEM768X25519_AES256GCM_SHA384_Ed25519,
            Ciphersuite::MLS_128_MLKEM768P256_AES128GCM_SHA256_P256,
            Ciphersuite::MLS_128_MLKEM768P256_AES256GCM_SHA384_P256,
            Ciphersuite::MLS_192_MLKEM1024P384_AES256GCM_SHA384_P384,
            Ciphersuite::MLS_128_MLKEM768_AES256GCM_SHA384_P256,
            Ciphersuite::MLS_192_MLKEM1024_AES256GCM_SHA384_P384,
            Ciphersuite::MLS_192_MLKEM768_AES256GCM_SHA384_MLDSA65,
            Ciphersuite::MLS_256_MLKEM1024_AES256GCM_SHA384_MLDSA87,
            Ciphersuite::MLS_128_MLKEM768_AES256GCM_SHA384_Ed25519,
            Ciphersuite::MLS_128_MLKEM768X25519_CHACHA20POLY1305_SHA384_MLDSA44,
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

    fn aead_decrypt(
        &self,
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

    /// Generate a `(secret key, public key)` pair from a signature scheme.
    fn signature_key_gen(&self, alg: SignatureScheme) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
        let mut rng = self.rng.write().map_err(|_| CryptoError::InsufficientRandomness)?;

        match alg {
            SignatureScheme::ECDSA_SECP256R1_SHA256 => {
                let sk = p256::ecdsa::SigningKey::generate_from_rng(&mut *rng);
                let pk = sk.verifying_key().to_sec1_bytes().to_vec();
                Ok((sk.to_bytes().to_vec(), pk))
            }
            SignatureScheme::ECDSA_SECP384R1_SHA384 => {
                let sk = p384::ecdsa::SigningKey::generate_from_rng(&mut *rng);
                let pk = sk.verifying_key().to_sec1_bytes().to_vec();
                Ok((sk.to_bytes().to_vec(), pk))
            }
            SignatureScheme::ECDSA_SECP521R1_SHA512 => {
                let sk = p521::ecdsa::SigningKey::generate_from_rng(&mut *rng);
                let pk = p521::ecdsa::VerifyingKey::from(&sk)
                    .to_sec1_point(false)
                    .to_bytes()
                    .into();
                Ok((sk.to_bytes().to_vec(), pk))
            }
            SignatureScheme::ED25519 => {
                let k = ed25519_dalek::SigningKey::generate(&mut *rng);
                let pk = k.verifying_key();
                Ok((k.to_bytes().into(), pk.to_bytes().into()))
            }
            SignatureScheme::MLDSA44 => mldsa::key_gen::<MlDsa44>(&mut *rng).map(|(sk, pk)| (sk.to_vec(), pk)),
            SignatureScheme::MLDSA65 => mldsa::key_gen::<MlDsa65>(&mut *rng).map(|(sk, pk)| (sk.to_vec(), pk)),
            SignatureScheme::MLDSA87 => mldsa::key_gen::<MlDsa87>(&mut *rng).map(|(sk, pk)| (sk.to_vec(), pk)),
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
            SignatureScheme::MLDSA44 => mldsa::validate_key::<MlDsa44>(key)?,
            SignatureScheme::MLDSA65 => mldsa::validate_key::<MlDsa65>(key)?,
            SignatureScheme::MLDSA87 => mldsa::validate_key::<MlDsa87>(key)?,
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
            SignatureScheme::MLDSA44 => mldsa::verify::<MlDsa44>(data, pk, signature),
            SignatureScheme::MLDSA65 => mldsa::verify::<MlDsa65>(data, pk, signature),
            SignatureScheme::MLDSA87 => mldsa::verify::<MlDsa87>(data, pk, signature),
            _ => Err(CryptoError::UnsupportedSignatureScheme),
        }
    }

    fn sign(&self, alg: SignatureScheme, data: &[u8], key: &[u8]) -> Result<Vec<u8>, CryptoError> {
        match alg {
            SignatureScheme::MLDSA44 => mldsa::sign::<MlDsa44>(data, key),
            SignatureScheme::MLDSA65 => mldsa::sign::<MlDsa65>(data, key),
            SignatureScheme::MLDSA87 => mldsa::sign::<MlDsa87>(data, key),
            // classical schemes are signed via the basic-credential crate, not here
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
        // seeded RNG into encap, so seal stays deterministic and avoids the OS RNG
        let mut rng = self.rng.write().map_err(|_| CryptoError::InsufficientRandomness)?;
        hpke_dispatch!(config, hpke_seal, pk_r, info, aad, ptxt, &mut *rng)
    }

    fn hpke_open(
        &self,
        config: HpkeConfig,
        input: &types::HpkeCiphertext,
        sk_r: &[u8],
        info: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        hpke_dispatch!(
            config,
            hpke_open,
            sk_r,
            input.kem_output.as_slice(),
            info,
            aad,
            input.ciphertext.as_slice(),
        )
    }

    fn hpke_setup_sender_and_export(
        &self,
        config: HpkeConfig,
        pk_r: &[u8],
        info: &[u8],
        exporter_context: &[u8],
        exporter_length: usize,
    ) -> Result<(Vec<u8>, ExporterSecret), CryptoError> {
        // same seeded-RNG handling as hpke_seal
        let mut rng = self.rng.write().map_err(|_| CryptoError::InsufficientRandomness)?;
        let (kem_output, export) = hpke_dispatch!(
            config,
            hpke_export_tx,
            pk_r,
            info,
            exporter_context,
            exporter_length,
            &mut *rng,
        )?;

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
        let export = hpke_dispatch!(
            config,
            hpke_export_rx,
            enc,
            sk_r,
            info,
            exporter_context,
            exporter_length,
        )?;

        debug_assert_eq!(export.len(), exporter_length);

        Ok(export.into())
    }

    fn derive_hpke_keypair(&self, config: HpkeConfig, ikm: &[u8]) -> Result<types::HpkeKeyPair, CryptoError> {
        hpke_kem_dispatch!(config.0, hpke_derive_keypair, ikm)
    }
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

    pub(crate) fn hpke_open_psk<Aead: hpke::aead::Aead, Kdf: hpke::kdf::Kdf, Kem: hpke::Kem>(
        private_key: &[u8],
        kem_output: &[u8],
        info: &[u8],
        aad: &[u8],
        psk: &[u8],
        psk_id: &[u8],
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

    #[allow(dead_code)]
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
        rng.fill_bytes(&mut out);
        Ok(out)
    }

    fn random_vec(&self, len: usize) -> Result<Vec<u8>, Self::Error> {
        let mut rng = self.borrow_rand()?;
        let mut out = vec![0u8; len];
        rng.fill_bytes(&mut out);
        Ok(out)
    }
}

// Wiring only: scheme dispatch, key lengths, malformed-key rejection.
// FIPS-204 conformance is the ml-dsa crate's job.
#[cfg(test)]
mod mldsa_tests {
    use openmls_traits::crypto::OpenMlsCrypto;

    use super::*;

    // (scheme, public key length, signature length) for the three ML-DSA variants
    const MLDSA44: (SignatureScheme, usize, usize) = (SignatureScheme::MLDSA44, 1312, 2420);
    const MLDSA65: (SignatureScheme, usize, usize) = (SignatureScheme::MLDSA65, 1952, 3309);
    const MLDSA87: (SignatureScheme, usize, usize) = (SignatureScheme::MLDSA87, 2592, 4627);

    #[test]
    fn keygen_sign_verify_round_trip() {
        for (scheme, pk_len, sig_len) in [MLDSA44, MLDSA65, MLDSA87] {
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
        for (scheme, pk_len, _) in [MLDSA44, MLDSA65, MLDSA87] {
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
        for (scheme, ..) in [MLDSA44, MLDSA65, MLDSA87] {
            let provider = RustCrypto::default();
            let (private_key, _) = provider.signature_key_gen(scheme).unwrap();
            let message = b"deterministic";
            let sig_a = provider.sign(scheme, message, &private_key).unwrap();
            let sig_b = provider.sign(scheme, message, &private_key).unwrap();
            assert_eq!(sig_a, sig_b, "signatures must be deterministic for {scheme:?}");
        }
    }
}

// what is left checks RNG determinism and every entry point per suite
#[cfg(test)]
mod pq_hpke_tests {
    use openmls_traits::{
        crypto::OpenMlsCrypto,
        types::{HpkeAeadType, HpkeConfig, HpkeKdfType, HpkeKemType},
    };

    use super::*;

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
                HpkeKdfType::HkdfSha384,
                HpkeAeadType::AesGcm256,
                0x22,
            ),
        ];

        for (kem, kdf, aead, ikm_byte) in cases {
            // fixed seed for both providers, so the RNG streams are identical
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

            let recovered = provider_a
                .hpke_open(HpkeConfig(kem, kdf, aead), &ct_a, &kp.private, info, aad)
                .unwrap_or_else(|e| panic!("hpke_open failed for ({kem:?},{kdf:?},{aead:?}): {e:?}"));
            assert_eq!(
                recovered, plaintext,
                "round-trip mismatch for ({kem:?},{kdf:?},{aead:?})"
            );
        }
    }

    #[test]
    fn every_supported_ciphersuite_reaches_every_hpke_entry_point() {
        let provider = RustCrypto::default();
        for ciphersuite in provider.supported_ciphersuites() {
            let kp = provider
                .derive_hpke_keypair(ciphersuite.hpke_config(), &[0x42u8; 64])
                .unwrap_or_else(|e| panic!("derive_hpke_keypair({ciphersuite:?}): {e:?}"));
            let sealed = provider
                .hpke_seal(ciphersuite.hpke_config(), &kp.public, b"info", b"aad", b"message")
                .unwrap_or_else(|e| panic!("hpke_seal({ciphersuite:?}): {e:?}"));
            provider
                .hpke_open(ciphersuite.hpke_config(), &sealed, &kp.private, b"info", b"aad")
                .unwrap_or_else(|e| panic!("hpke_open({ciphersuite:?}): {e:?}"));
            let (enc, _) = provider
                .hpke_setup_sender_and_export(ciphersuite.hpke_config(), &kp.public, b"info", b"exporter", 32)
                .unwrap_or_else(|e| panic!("hpke_setup_sender_and_export({ciphersuite:?}): {e:?}"));
            provider
                .hpke_setup_receiver_and_export(ciphersuite.hpke_config(), &enc, &kp.private, b"info", b"exporter", 32)
                .unwrap_or_else(|e| panic!("hpke_setup_receiver_and_export({ciphersuite:?}): {e:?}"));
            let psk = [0x11u8; 32];
            let psk_id = b"psk-id";
            let sealed_psk = provider
                .hpke_seal_psk(
                    ciphersuite.hpke_config(),
                    &kp.public,
                    b"info",
                    b"aad",
                    &psk,
                    psk_id,
                    b"message",
                )
                .unwrap_or_else(|e| panic!("hpke_seal_psk({ciphersuite:?}): {e:?}"));
            provider
                .hpke_open_psk(
                    ciphersuite.hpke_config(),
                    &sealed_psk,
                    &kp.private,
                    b"info",
                    b"aad",
                    &psk,
                    psk_id,
                )
                .unwrap_or_else(|e| panic!("hpke_open_psk({ciphersuite:?}): {e:?}"));
        }
    }
}
