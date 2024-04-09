use crate::EntropySeed;
use crate::MlsProviderError;
use rand_core::{RngCore, SeedableRng};
use signature::digest::typenum::Unsigned;
use std::sync::RwLock;

use aes_gcm::{
    aead::{Aead, Payload},
    Aes128Gcm, Aes256Gcm, KeyInit,
};
use chacha20poly1305::ChaCha20Poly1305;
use hkdf::Hkdf;
use openmls_traits::{
    crypto::OpenMlsCrypto,
    random::OpenMlsRand,
    types::{
        self, AeadType, Ciphersuite, CryptoError, ExporterSecret, HashType, HpkeAeadType, HpkeConfig, HpkeKdfType,
        HpkeKemType, SignatureScheme,
    },
};
use sha2::{Digest, Sha256, Sha384, Sha512};
use tls_codec::SecretVLBytes;

#[derive(Debug)]
pub struct RustCrypto {
    pub(crate) rng: RwLock<rand_chacha::ChaCha20Rng>,
}

impl Default for RustCrypto {
    fn default() -> Self {
        Self {
            rng: RwLock::new(rand_chacha::ChaCha20Rng::from_entropy()),
        }
    }
}

#[inline]
fn normalize_p521_secret_key(sk: &[u8]) -> zeroize::Zeroizing<[u8; 66]> {
    let mut sk_buf = zeroize::Zeroizing::new([0u8; 66]);
    sk_buf[66 - sk.len()..].copy_from_slice(sk);
    sk_buf
}

impl RustCrypto {
    pub fn new_with_seed(seed: EntropySeed) -> Self {
        Self {
            rng: rand_chacha::ChaCha20Rng::from_seed(seed.0).into(),
        }
    }

    pub fn normalize_p521_secret_key(sk: &[u8]) -> zeroize::Zeroizing<[u8; 66]> {
        normalize_p521_secret_key(sk)
    }

    pub fn normalize_ed25519_key(key: &[u8]) -> Result<ed25519_dalek::SigningKey, CryptoError> {
        let k = match key.len() {
            // Compat layer for legacy keypairs [seed, pk]
            ed25519_dalek::KEYPAIR_LENGTH => {
                let mut sk = zeroize::Zeroizing::new([0u8; ed25519_dalek::KEYPAIR_LENGTH]);
                sk.copy_from_slice(key);
                ed25519_dalek::SigningKey::from_keypair_bytes(&sk).map_err(|_| CryptoError::CryptoLibraryError)?
            }
            ed25519_dalek::SECRET_KEY_LENGTH => {
                let mut sk = zeroize::Zeroizing::new([0u8; ed25519_dalek::SECRET_KEY_LENGTH]);
                sk.copy_from_slice(key);
                ed25519_dalek::SigningKey::from_bytes(&sk)
            }
            _ => return Err(CryptoError::CryptoLibraryError),
        };
        Ok(k)
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
        }
    }

    fn supports(&self, ciphersuite: Ciphersuite) -> Result<(), CryptoError> {
        match ciphersuite {
            Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519
            | Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519
            | Ciphersuite::MLS_128_DHKEMP256_AES128GCM_SHA256_P256
            | Ciphersuite::MLS_256_DHKEMP384_AES256GCM_SHA384_P384
            | Ciphersuite::MLS_256_DHKEMP521_AES256GCM_SHA512_P521
            | Ciphersuite::MLS_128_X25519KYBER768DRAFT00_AES128GCM_SHA256_Ed25519 => Ok(()),
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
            Ciphersuite::MLS_128_X25519KYBER768DRAFT00_AES128GCM_SHA256_Ed25519,
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
            _ => Err(CryptoError::UnsupportedSignatureScheme),
        }
    }

    fn sign(&self, alg: SignatureScheme, data: &[u8], key: &[u8]) -> Result<Vec<u8>, CryptoError> {
        use signature::Signer as _;

        match alg {
            SignatureScheme::ECDSA_SECP256R1_SHA256 => {
                let k = p256::ecdsa::SigningKey::from_slice(key).map_err(|_| CryptoError::CryptoLibraryError)?;
                let signature: p256::ecdsa::DerSignature =
                    k.try_sign(data).map_err(|_| CryptoError::CryptoLibraryError)?;
                Ok(signature.to_bytes().into())
            }
            SignatureScheme::ECDSA_SECP384R1_SHA384 => {
                let k = p384::ecdsa::SigningKey::from_slice(key).map_err(|_| CryptoError::CryptoLibraryError)?;
                let signature: p384::ecdsa::DerSignature =
                    k.try_sign(data).map_err(|_| CryptoError::CryptoLibraryError)?;
                Ok(signature.to_bytes().into())
            }
            SignatureScheme::ECDSA_SECP521R1_SHA512 => {
                let k = p521::ecdsa::SigningKey::from_slice(&*normalize_p521_secret_key(key))
                    .map_err(|_| CryptoError::CryptoLibraryError)?;
                let signature: p521::ecdsa::DerSignature =
                    k.try_sign(data).map_err(|_| CryptoError::CryptoLibraryError)?.to_der();
                Ok(signature.to_bytes().into())
            }
            SignatureScheme::ED25519 => {
                let k = Self::normalize_ed25519_key(key)?;
                let signature = k.try_sign(data).map_err(|_| CryptoError::CryptoLibraryError)?;
                Ok(signature.to_bytes().into())
            }
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
        let mut rng = self.rng.write().map_err(|_| CryptoError::InsufficientRandomness)?;

        match config {
            HpkeConfig(HpkeKemType::DhKem25519, HpkeKdfType::HkdfSha256, HpkeAeadType::AesGcm128) => {
                hpke_core::hpke_seal::<hpke::aead::AesGcm128, hpke::kdf::HkdfSha256, hpke::kem::X25519HkdfSha256>(
                    pk_r, info, aad, ptxt, &mut *rng,
                )
            }
            HpkeConfig(HpkeKemType::DhKem25519, HpkeKdfType::HkdfSha256, HpkeAeadType::ChaCha20Poly1305) => {
                hpke_core::hpke_seal::<hpke::aead::ChaCha20Poly1305, hpke::kdf::HkdfSha256, hpke::kem::X25519HkdfSha256>(
                    pk_r, info, aad, ptxt, &mut *rng,
                )
            }
            HpkeConfig(HpkeKemType::DhKemP256, HpkeKdfType::HkdfSha256, HpkeAeadType::AesGcm128) => {
                hpke_core::hpke_seal::<hpke::aead::AesGcm128, hpke::kdf::HkdfSha256, hpke::kem::DhP256HkdfSha256>(
                    pk_r, info, aad, ptxt, &mut *rng,
                )
            }
            HpkeConfig(HpkeKemType::DhKemP384, HpkeKdfType::HkdfSha384, HpkeAeadType::AesGcm256) => {
                hpke_core::hpke_seal::<hpke::aead::AesGcm256, hpke::kdf::HkdfSha384, hpke::kem::DhP384HkdfSha384>(
                    pk_r, info, aad, ptxt, &mut *rng,
                )
            }
            HpkeConfig(HpkeKemType::DhKemP521, HpkeKdfType::HkdfSha512, HpkeAeadType::AesGcm256) => {
                hpke_core::hpke_seal::<hpke::aead::AesGcm256, hpke::kdf::HkdfSha512, hpke::kem::DhP521HkdfSha512>(
                    pk_r, info, aad, ptxt, &mut *rng,
                )
            }
            HpkeConfig(HpkeKemType::X25519Kyber768Draft00, HpkeKdfType::HkdfSha256, HpkeAeadType::AesGcm128) => {
                hpke_core::hpke_seal::<hpke::aead::AesGcm128, hpke::kdf::HkdfSha256, hpke::kem::X25519Kyber768Draft00>(
                    pk_r, info, aad, ptxt, &mut *rng,
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
            HpkeConfig(HpkeKemType::X25519Kyber768Draft00, HpkeKdfType::HkdfSha256, HpkeAeadType::AesGcm128) => {
                hpke_core::hpke_open::<hpke::aead::AesGcm128, hpke::kdf::HkdfSha256, hpke::kem::X25519Kyber768Draft00>(
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
        let mut rng = self.rng.write().map_err(|_| CryptoError::InsufficientRandomness)?;

        let (kem_output, export) =
            match config {
                HpkeConfig(HpkeKemType::DhKem25519, HpkeKdfType::HkdfSha256, HpkeAeadType::AesGcm128) => {
                    hpke_core::hpke_export_tx::<
                        hpke::aead::AesGcm128,
                        hpke::kdf::HkdfSha256,
                        hpke::kem::X25519HkdfSha256,
                    >(pk_r, info, exporter_context, exporter_length, &mut *rng)?
                }
                HpkeConfig(HpkeKemType::DhKem25519, HpkeKdfType::HkdfSha256, HpkeAeadType::ChaCha20Poly1305) => {
                    hpke_core::hpke_export_tx::<
                        hpke::aead::ChaCha20Poly1305,
                        hpke::kdf::HkdfSha256,
                        hpke::kem::X25519HkdfSha256,
                    >(pk_r, info, exporter_context, exporter_length, &mut *rng)?
                }
                HpkeConfig(HpkeKemType::DhKemP256, HpkeKdfType::HkdfSha256, HpkeAeadType::AesGcm128) => {
                    hpke_core::hpke_export_tx::<
                        hpke::aead::AesGcm128,
                        hpke::kdf::HkdfSha256,
                        hpke::kem::DhP256HkdfSha256,
                    >(pk_r, info, exporter_context, exporter_length, &mut *rng)?
                }
                HpkeConfig(HpkeKemType::DhKemP384, HpkeKdfType::HkdfSha384, HpkeAeadType::AesGcm256) => {
                    hpke_core::hpke_export_tx::<
                        hpke::aead::AesGcm256,
                        hpke::kdf::HkdfSha384,
                        hpke::kem::DhP384HkdfSha384,
                    >(pk_r, info, exporter_context, exporter_length, &mut *rng)?
                }
                HpkeConfig(HpkeKemType::DhKemP521, HpkeKdfType::HkdfSha512, HpkeAeadType::AesGcm256) => {
                    hpke_core::hpke_export_tx::<
                        hpke::aead::AesGcm256,
                        hpke::kdf::HkdfSha512,
                        hpke::kem::DhP521HkdfSha512,
                    >(pk_r, info, exporter_context, exporter_length, &mut *rng)?
                }
                HpkeConfig(HpkeKemType::X25519Kyber768Draft00, HpkeKdfType::HkdfSha256, HpkeAeadType::AesGcm128) => {
                    hpke_core::hpke_export_tx::<
                        hpke::aead::AesGcm128,
                        hpke::kdf::HkdfSha256,
                        hpke::kem::X25519Kyber768Draft00,
                    >(pk_r, info, exporter_context, exporter_length, &mut *rng)?
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
        let export =
            match config {
                HpkeConfig(HpkeKemType::DhKem25519, HpkeKdfType::HkdfSha256, HpkeAeadType::AesGcm128) => {
                    hpke_core::hpke_export_rx::<
                        hpke::aead::AesGcm128,
                        hpke::kdf::HkdfSha256,
                        hpke::kem::X25519HkdfSha256,
                    >(enc, sk_r, info, exporter_context, exporter_length)?
                }
                HpkeConfig(HpkeKemType::DhKem25519, HpkeKdfType::HkdfSha256, HpkeAeadType::ChaCha20Poly1305) => {
                    hpke_core::hpke_export_rx::<
                        hpke::aead::ChaCha20Poly1305,
                        hpke::kdf::HkdfSha256,
                        hpke::kem::X25519HkdfSha256,
                    >(enc, sk_r, info, exporter_context, exporter_length)?
                }
                HpkeConfig(HpkeKemType::DhKemP256, HpkeKdfType::HkdfSha256, HpkeAeadType::AesGcm128) => {
                    hpke_core::hpke_export_rx::<
                        hpke::aead::AesGcm128,
                        hpke::kdf::HkdfSha256,
                        hpke::kem::DhP256HkdfSha256,
                    >(enc, sk_r, info, exporter_context, exporter_length)?
                }
                HpkeConfig(HpkeKemType::DhKemP384, HpkeKdfType::HkdfSha384, HpkeAeadType::AesGcm256) => {
                    hpke_core::hpke_export_rx::<
                        hpke::aead::AesGcm256,
                        hpke::kdf::HkdfSha384,
                        hpke::kem::DhP384HkdfSha384,
                    >(enc, sk_r, info, exporter_context, exporter_length)?
                }
                HpkeConfig(HpkeKemType::DhKemP521, HpkeKdfType::HkdfSha512, HpkeAeadType::AesGcm256) => {
                    hpke_core::hpke_export_rx::<
                        hpke::aead::AesGcm256,
                        hpke::kdf::HkdfSha512,
                        hpke::kem::DhP521HkdfSha512,
                    >(enc, sk_r, info, exporter_context, exporter_length)?
                }
                HpkeConfig(HpkeKemType::X25519Kyber768Draft00, HpkeKdfType::HkdfSha256, HpkeAeadType::AesGcm128) => {
                    hpke_core::hpke_export_rx::<
                        hpke::aead::AesGcm128,
                        hpke::kdf::HkdfSha256,
                        hpke::kem::X25519Kyber768Draft00,
                    >(enc, sk_r, info, exporter_context, exporter_length)?
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
            HpkeKemType::X25519Kyber768Draft00 => {
                hpke_core::hpke_derive_keypair::<hpke::kem::X25519Kyber768Draft00>(ikm)
            }
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
        csprng: &mut impl rand_core::CryptoRngCore,
    ) -> Result<HpkeCiphertext, CryptoError> {
        use hpke::{Deserializable as _, Serializable as _};
        let key = Kem::PublicKey::from_bytes(public_key).map_err(|_| CryptoError::HpkeEncryptionError)?;
        let (encapped, ciphertext) =
            hpke::single_shot_seal::<Aead, Kdf, Kem, _>(&hpke::OpModeS::Base, &key, info, plaintext, aad, csprng)
                .map_err(|_| CryptoError::HpkeEncryptionError)?;

        Ok(HpkeCiphertext {
            kem_output: encapped.to_bytes().to_vec().into(),
            ciphertext: ciphertext.into(),
        })
    }

    #[allow(dead_code)]
    pub(crate) fn hpke_gen_keypair<Kem: hpke::Kem>(
        csprng: &mut impl rand_core::CryptoRngCore,
    ) -> Result<HpkeKeyPair, CryptoError> {
        use hpke::Serializable as _;
        let (sk, pk) = Kem::gen_keypair(csprng);
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
        csprng: &mut impl rand_core::CryptoRngCore,
    ) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
        use hpke::{Deserializable as _, Serializable as _};
        let key = Kem::PublicKey::from_bytes(tx_public_key).map_err(|_| CryptoError::SenderSetupError)?;
        let (kem_output, ctx) = hpke::setup_sender::<Aead, Kdf, Kem, _>(&hpke::OpModeS::Base, &key, info, csprng)
            .map_err(|_| CryptoError::SenderSetupError)?;

        let mut export = vec![0u8; export_len];

        ctx.export(export_info, &mut export)
            .map_err(|_| CryptoError::ExporterError)?;

        Ok((kem_output.to_bytes().to_vec(), export))
    }
}

impl OpenMlsRand for RustCrypto {
    type Error = MlsProviderError;

    type RandImpl = rand_chacha::ChaCha20Rng;
    type BorrowTarget<'a> = std::sync::RwLockWriteGuard<'a, Self::RandImpl>;

    fn borrow_rand(&self) -> Result<Self::BorrowTarget<'_>, Self::Error> {
        self.rng.write().map_err(|_| MlsProviderError::RngLockPoison)
    }

    fn random_array<const N: usize>(&self) -> Result<[u8; N], Self::Error> {
        let mut rng = self.borrow_rand()?;
        let mut out = [0u8; N];
        rng.try_fill_bytes(&mut out)
            .map_err(|_| MlsProviderError::UnsufficientEntropy)?;
        Ok(out)
    }

    fn random_vec(&self, len: usize) -> Result<Vec<u8>, Self::Error> {
        let mut rng = self.borrow_rand()?;
        let mut out = vec![0u8; len];
        rng.try_fill_bytes(&mut out)
            .map_err(|_| MlsProviderError::UnsufficientEntropy)?;
        Ok(out)
    }
}
