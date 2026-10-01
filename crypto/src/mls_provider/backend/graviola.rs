//! The graviola implementation of the primitives. Where graviola has nothing to offer (P521, or
//! a scheme we do not support at all), we delegate to the [`rustcrypto`] backend, so its behavior
//! for those cases is by construction identical.
//!
//! Every function here returns the same byte encodings as its [`rustcrypto`] counterpart.

use graviola::{
    aead::{AesGcm, ChaCha20Poly1305},
    hashing::{Hash as _, Sha256, Sha384, Sha512},
    key_agreement,
    signing::{
        ecdsa,
        eddsa::{Ed25519SigningKey, Ed25519VerifyingKey},
    },
};
use openmls_traits::types::{AeadType, CryptoError, HashType, SignatureScheme};
use rand::Rng as _;

use super::rustcrypto;

pub(crate) fn hash(hash_type: HashType, data: &[u8]) -> Result<Vec<u8>, CryptoError> {
    match hash_type {
        HashType::Sha2_256 => Ok(Sha256::hash(data).as_ref().to_vec()),
        HashType::Sha2_384 => Ok(Sha384::hash(data).as_ref().to_vec()),
        HashType::Sha2_512 => Ok(Sha512::hash(data).as_ref().to_vec()),
    }
}

// graviola encrypts in place and writes the authentication tag to a separate buffer, but
// openmls expects the tag appended to the ciphertext.
// The key-length guards match the error behaviour of the rustcrypto path, since graviola's
// `AesGcm::new` panics on an invalid length.
pub(crate) fn aead_encrypt(
    alg: AeadType,
    key: &[u8],
    data: &[u8],
    nonce: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let nonce: &[u8; 12] = nonce.try_into().map_err(|_| CryptoError::CryptoLibraryError)?;
    let mut buf = data.to_vec();
    let mut tag = [0u8; 16];

    match alg {
        AeadType::Aes128Gcm => {
            if key.len() != 16 {
                return Err(CryptoError::CryptoLibraryError);
            }
            AesGcm::new(key).encrypt(nonce, aad, &mut buf, &mut tag);
        }
        AeadType::Aes256Gcm => {
            if key.len() != 32 {
                return Err(CryptoError::CryptoLibraryError);
            }
            AesGcm::new(key).encrypt(nonce, aad, &mut buf, &mut tag);
        }
        AeadType::ChaCha20Poly1305 => {
            let key: [u8; 32] = key.try_into().map_err(|_| CryptoError::CryptoLibraryError)?;
            ChaCha20Poly1305::new(key).encrypt(nonce, aad, &mut buf, &mut tag);
        }
    }

    buf.extend_from_slice(&tag);
    Ok(buf)
}

// `openmls` supplies the ciphertext with the authentication tag appended, which we split off
// before handing the ciphertext to graviola's in-place decryption. See [`aead_encrypt`].
pub(crate) fn aead_decrypt(
    alg: AeadType,
    key: &[u8],
    ct_tag: &[u8],
    nonce: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let nonce: &[u8; 12] = nonce.try_into().map_err(|_| CryptoError::CryptoLibraryError)?;

    // The trailing 16 bytes are the authentication tag.
    if ct_tag.len() < 16 {
        return Err(CryptoError::AeadDecryptionError);
    }
    let (ciphertext, tag) = ct_tag.split_at(ct_tag.len() - 16);
    let mut buf = ciphertext.to_vec();

    match alg {
        AeadType::Aes128Gcm => {
            if key.len() != 16 {
                return Err(CryptoError::CryptoLibraryError);
            }
            AesGcm::new(key)
                .decrypt(nonce, aad, &mut buf, tag)
                .map_err(|_| CryptoError::AeadDecryptionError)?;
        }
        AeadType::Aes256Gcm => {
            if key.len() != 32 {
                return Err(CryptoError::CryptoLibraryError);
            }
            AesGcm::new(key)
                .decrypt(nonce, aad, &mut buf, tag)
                .map_err(|_| CryptoError::AeadDecryptionError)?;
        }
        AeadType::ChaCha20Poly1305 => {
            let key: [u8; 32] = key.try_into().map_err(|_| CryptoError::CryptoLibraryError)?;
            ChaCha20Poly1305::new(key)
                .decrypt(nonce, aad, &mut buf, tag)
                .map_err(|_| CryptoError::AeadDecryptionError)?;
        }
    }

    Ok(buf)
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
    match alg {
        SignatureScheme::ECDSA_SECP256R1_SHA256 => {
            // graviola exposes no key generation on `signing::ecdsa`, but its `key_agreement`
            // P256 key is the same underlying scalar with identical byte encodings. We sample a
            // scalar ourselves and reject the (negligibly rare) out-of-range or zero values.
            let sk = loop {
                let mut scalar = [0u8; 32];
                rng.fill_bytes(&mut scalar);
                if let Ok(sk) = key_agreement::p256::StaticPrivateKey::from_bytes(&scalar) {
                    break sk;
                }
            };
            Ok((sk.as_bytes().to_vec(), sk.public_key_uncompressed().to_vec()))
        }
        SignatureScheme::ECDSA_SECP384R1_SHA384 => {
            let sk = loop {
                let mut scalar = [0u8; 48];
                rng.fill_bytes(&mut scalar);
                if let Ok(sk) = key_agreement::p384::StaticPrivateKey::from_bytes(&scalar) {
                    break sk;
                }
            };
            Ok((sk.as_bytes().to_vec(), sk.public_key_uncompressed().to_vec()))
        }
        SignatureScheme::ED25519 => {
            // Any 32 bytes are a valid Ed25519 seed, so no rejection sampling is needed.
            let mut seed = [0u8; 32];
            rng.fill_bytes(&mut seed);
            let sk = Ed25519SigningKey::from_bytes(&seed).map_err(|_| CryptoError::CryptoLibraryError)?;
            Ok((sk.as_seed().to_vec(), sk.public_key().as_bytes().to_vec()))
        }
        _ => rustcrypto::signature_key_gen(alg, rng),
    }
}

pub(crate) fn validate_signature_key(alg: SignatureScheme, key: &[u8]) -> Result<(), CryptoError> {
    match alg {
        SignatureScheme::ED25519 => {
            Ed25519VerifyingKey::from_bytes(key).map_err(|_| CryptoError::InvalidKey)?;
            Ok(())
        }
        SignatureScheme::ECDSA_SECP256R1_SHA256 => {
            ecdsa::VerifyingKey::<ecdsa::P256>::from_x962_uncompressed(key).map_err(|_| CryptoError::InvalidKey)?;
            Ok(())
        }
        SignatureScheme::ECDSA_SECP384R1_SHA384 => {
            ecdsa::VerifyingKey::<ecdsa::P384>::from_x962_uncompressed(key).map_err(|_| CryptoError::InvalidKey)?;
            Ok(())
        }
        _ => rustcrypto::validate_signature_key(alg, key),
    }
}

pub(crate) fn verify_signature(
    alg: SignatureScheme,
    data: &[u8],
    pk: &[u8],
    signature: &[u8],
) -> Result<(), CryptoError> {
    match alg {
        SignatureScheme::ECDSA_SECP256R1_SHA256 => {
            let k = ecdsa::VerifyingKey::<ecdsa::P256>::from_x962_uncompressed(pk)
                .map_err(|_| CryptoError::CryptoLibraryError)?;
            k.verify_asn1::<Sha256>(&[data], signature)
                .map_err(|_| CryptoError::InvalidSignature)
        }
        SignatureScheme::ECDSA_SECP384R1_SHA384 => {
            let k = ecdsa::VerifyingKey::<ecdsa::P384>::from_x962_uncompressed(pk)
                .map_err(|_| CryptoError::CryptoLibraryError)?;
            k.verify_asn1::<Sha384>(&[data], signature)
                .map_err(|_| CryptoError::InvalidSignature)
        }
        SignatureScheme::ED25519 => {
            let k = Ed25519VerifyingKey::from_bytes(pk).map_err(|_| CryptoError::CryptoLibraryError)?;
            k.verify(signature, data).map_err(|_| CryptoError::InvalidSignature)
        }
        _ => rustcrypto::verify_signature(alg, data, pk, signature),
    }
}
