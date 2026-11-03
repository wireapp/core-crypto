//! The RustCrypto implementation of the primitives. This is always compiled: it is the only
//! backend on architectures graviola does not support, and the fallback for P521 and for CPUs which
//! lack the features graviola requires.

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
    types::{AeadType, CryptoError, HashType, SignatureScheme},
};
use sha2::{Digest as _, Sha256, Sha384, Sha512};
use tls_codec::SecretVLBytes;

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
