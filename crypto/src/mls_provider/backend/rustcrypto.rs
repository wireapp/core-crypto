//! The RustCrypto implementation of the primitives. This is always compiled: it is the only
//! backend on architectures graviola does not support, and the fallback for P521 and for CPUs which
//! lack the features graviola requires.

use aes_gcm::{
    Aes128Gcm, Aes256Gcm, KeyInit,
    aead::{Aead, Nonce, Payload},
};
use chacha20poly1305::ChaCha20Poly1305;
use elliptic_curve::Generate as _;
use openmls_traits::types::{AeadType, CryptoError, HashType, SignatureScheme};
use sha2::{Digest as _, Sha256, Sha384, Sha512};

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
        _ => Err(CryptoError::UnsupportedSignatureScheme),
    }
}
