//! Implementations of the primitives for which we prefer [graviola] where it is available.
//!
//! [`rustcrypto`] is always compiled and is the only backend on architectures graviola does not
//! support. On those it does support, [`graviola`] is compiled as well, and is used whenever the
//! CPU we are actually running on has the features it requires; see [`graviola_supported`].
//!
//! [graviola]: https://github.com/ctz/graviola

use openmls_traits::types::{AeadType, CryptoError, HashType, SignatureScheme};

#[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
mod graviola;
mod rustcrypto;

/// Whether the CPU we are running on has every feature graviola requires.
///
/// graviola asserts its required CPU features on first use and panics if any is missing, which
/// is not something we can recover from, so we must not call it unless this returns `true`. The
/// result cannot be determined at build time, because it depends on the machine the binary runs
/// on, not the one it was built on.
///
/// This duplicates the list of features graviola requires, and must be kept in sync with it.
/// The authoritative list is `verify_cpu_features` in graviola's `low/x86_64/cpu.rs` (and
/// `low/aarch64/cpu.rs` for aarch64), at the revision pinned in `crypto/Cargo.toml`, e.g.
/// <https://github.com/ctz/graviola/blob/1a9dfcde985638c05b8fe192639c2e7a8ca763dc/graviola/src/low/x86_64/cpu.rs>.
#[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
fn graviola_supported() -> bool {
    static SUPPORTED: std::sync::LazyLock<bool> = std::sync::LazyLock::new(detect_graviola_support);
    *SUPPORTED
}

#[cfg(target_arch = "x86_64")]
fn detect_graviola_support() -> bool {
    std::is_x86_feature_detected!("aes")
        && std::is_x86_feature_detected!("pclmulqdq")
        && std::is_x86_feature_detected!("bmi1")
        && std::is_x86_feature_detected!("adx")
        && std::is_x86_feature_detected!("avx")
        && std::is_x86_feature_detected!("avx2")
}

#[cfg(target_arch = "aarch64")]
fn detect_graviola_support() -> bool {
    std::arch::is_aarch64_feature_detected!("neon")
        && std::arch::is_aarch64_feature_detected!("aes")
        && std::arch::is_aarch64_feature_detected!("pmull")
        && std::arch::is_aarch64_feature_detected!("sha2")
}

/// Call `$f` on the graviola backend if it is available here, and on the rustcrypto backend
/// otherwise.
macro_rules! dispatch {
    ($f:ident($($arg:expr),* $(,)?)) => {{
        #[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
        if graviola_supported() {
            return graviola::$f($($arg),*);
        }
        rustcrypto::$f($($arg),*)
    }};
}

pub(super) fn hash(hash_type: HashType, data: &[u8]) -> Result<Vec<u8>, CryptoError> {
    dispatch!(hash(hash_type, data))
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

/// The two backends are interchangeable at runtime, chosen by the CPU we happen to run on, so
/// anything one produces the other must accept, and where both reject an input they must agree
/// on why. These tests hold that contract; they run only where both backends are available.
#[cfg(all(test, any(target_arch = "aarch64", target_arch = "x86_64")))]
mod tests {
    use openmls_traits::types::{AeadType, CryptoError, HashType, SignatureScheme};
    use rand_core::SeedableRng as _;
    use signature::Signer as _;

    use super::{graviola, graviola_supported, rustcrypto};

    /// Returns `false`, after saying so, when this CPU lacks what graviola needs.
    /// Calling graviola in that case would panic.
    fn both_backends_available() -> bool {
        let available = graviola_supported();
        if !available {
            eprintln!("skipping: this CPU lacks features graviola requires");
        }
        available
    }

    fn rng(seed: u8) -> rand_chacha::ChaCha20Rng {
        rand_chacha::ChaCha20Rng::from_seed([seed; 32])
    }

    /// `(description, key, ciphertext, nonce, aad)`
    type AeadCase<'a> = (&'a str, &'a [u8], &'a [u8], &'a [u8], &'a [u8]);
    /// `(description, message, public key, signature)`
    type VerifyCase<'a> = (&'a str, &'a [u8], &'a [u8], &'a [u8]);

    const MESSAGE: &[u8] = b"a message which gets signed and verified";

    const AEADS: [(AeadType, usize); 3] = [
        (AeadType::Aes128Gcm, 16),
        (AeadType::Aes256Gcm, 32),
        (AeadType::ChaCha20Poly1305, 32),
    ];

    #[test]
    fn hashes_agree() {
        if !both_backends_available() {
            return;
        }
        let long = vec![0xa5; 10_000];
        for hash_type in [HashType::Sha2_256, HashType::Sha2_384, HashType::Sha2_512] {
            for data in [&[][..], b"abc", &long] {
                assert_eq!(
                    graviola::hash(hash_type, data),
                    rustcrypto::hash(hash_type, data),
                    "{hash_type:?} over {} bytes",
                    data.len()
                );
            }
        }
    }

    #[test]
    fn aead_output_is_identical_and_decrypts_on_either_backend() {
        if !both_backends_available() {
            return;
        }
        let nonce = [7u8; 12];
        for (alg, key_len) in AEADS {
            let key = vec![0x42; key_len];
            for plaintext in [&[][..], b"x", &[0x5a; 1000]] {
                let from_graviola = graviola::aead_encrypt(alg, &key, plaintext, &nonce, b"aad").unwrap();
                let from_rustcrypto = rustcrypto::aead_encrypt(alg, &key, plaintext, &nonce, b"aad").unwrap();
                assert_eq!(from_graviola, from_rustcrypto, "{alg:?}: ciphertext and tag");

                assert_eq!(
                    graviola::aead_decrypt(alg, &key, &from_rustcrypto, &nonce, b"aad").as_deref(),
                    Ok(plaintext),
                    "{alg:?}: graviola decrypts rustcrypto output"
                );
                assert_eq!(
                    rustcrypto::aead_decrypt(alg, &key, &from_graviola, &nonce, b"aad").as_deref(),
                    Ok(plaintext),
                    "{alg:?}: rustcrypto decrypts graviola output"
                );
            }
        }
    }

    /// Malformed inputs must produce the same error whichever backend happens to be in use.
    #[test]
    fn aead_rejects_bad_input_identically() {
        if !both_backends_available() {
            return;
        }
        let nonce = [7u8; 12];
        for (alg, key_len) in AEADS {
            let key = vec![0x42; key_len];
            let mut ciphertext = rustcrypto::aead_encrypt(alg, &key, b"plaintext", &nonce, b"aad").unwrap();
            let mut tampered = ciphertext.clone();
            *tampered.last_mut().unwrap() ^= 1;
            ciphertext.truncate(8); // shorter than the tag

            let cases: [AeadCase; 6] = [
                ("tampered tag", &key, &tampered, &nonce, b"aad"),
                ("wrong aad", &key, &tampered[..], &nonce, b"other"),
                ("shorter than the tag", &key, &ciphertext, &nonce, b"aad"),
                ("short key", &key[1..], &tampered, &nonce, b"aad"),
                ("long key", &[&key[..], &[0]].concat(), &tampered, &nonce, b"aad"),
                ("short nonce", &key, &tampered, &nonce[1..], b"aad"),
            ];
            for (case, key, ct, nonce, aad) in cases {
                let expected = rustcrypto::aead_decrypt(alg, key, ct, nonce, aad);
                assert!(expected.is_err(), "{alg:?}, {case}: rustcrypto must reject this");
                assert_eq!(
                    graviola::aead_decrypt(alg, key, ct, nonce, aad),
                    expected,
                    "{alg:?}, {case}: decrypt"
                );
            }

            for (case, key, nonce) in [
                ("short key", &key[1..], &nonce[..]),
                ("long key", &[&key[..], &[0]].concat(), &nonce),
                ("short nonce", &key, &nonce[1..]),
            ] {
                let expected = rustcrypto::aead_encrypt(alg, key, b"plaintext", nonce, b"aad");
                assert!(expected.is_err(), "{alg:?}, {case}: rustcrypto must reject this");
                assert_eq!(
                    graviola::aead_encrypt(alg, key, b"plaintext", nonce, b"aad"),
                    expected,
                    "{alg:?}, {case}: encrypt"
                );
            }
        }
    }

    const SCHEMES: [SignatureScheme; 4] = [
        SignatureScheme::ECDSA_SECP256R1_SHA256,
        SignatureScheme::ECDSA_SECP384R1_SHA384,
        SignatureScheme::ECDSA_SECP521R1_SHA512,
        SignatureScheme::ED25519,
    ];

    /// Sign `MESSAGE` with a secret key in the encoding that `signature_key_gen` emits, using the
    /// rustcrypto crates directly, in the encoding `verify_signature` expects.
    ///
    /// Also checks that the public key `signature_key_gen` returned is the one belonging to that
    /// secret key; the two backends must agree on what the bytes they emit mean.
    fn sign(scheme: SignatureScheme, sk: &[u8], pk: &[u8]) -> Vec<u8> {
        match scheme {
            SignatureScheme::ECDSA_SECP256R1_SHA256 => {
                let sk = p256::ecdsa::SigningKey::from_slice(sk).unwrap();
                assert_eq!(sk.verifying_key().to_sec1_point(false).as_bytes(), pk);
                let signature: p256::ecdsa::DerSignature = sk.sign(MESSAGE);
                signature.as_bytes().to_vec()
            }
            SignatureScheme::ECDSA_SECP384R1_SHA384 => {
                let sk = p384::ecdsa::SigningKey::from_slice(sk).unwrap();
                assert_eq!(sk.verifying_key().to_sec1_point(false).as_bytes(), pk);
                let signature: p384::ecdsa::DerSignature = sk.sign(MESSAGE);
                signature.as_bytes().to_vec()
            }
            SignatureScheme::ECDSA_SECP521R1_SHA512 => {
                let sk = p521::ecdsa::SigningKey::from_slice(sk).unwrap();
                assert_eq!(p521::ecdsa::VerifyingKey::from(&sk).to_sec1_point(false).as_bytes(), pk);
                let signature: p521::ecdsa::Signature = sk.sign(MESSAGE);
                signature.to_der().as_bytes().to_vec()
            }
            SignatureScheme::ED25519 => {
                let sk = ed25519_dalek::SigningKey::from_bytes(sk.try_into().unwrap());
                assert_eq!(sk.verifying_key().as_bytes(), pk);
                sk.sign(MESSAGE).to_bytes().to_vec()
            }
            other => unreachable!("not exercised: {other:?}"),
        }
    }

    #[test]
    fn keys_from_either_backend_are_interchangeable() {
        if !both_backends_available() {
            return;
        }
        for scheme in SCHEMES {
            let from_graviola = graviola::signature_key_gen(scheme, &mut rng(1)).unwrap();
            let from_rustcrypto = rustcrypto::signature_key_gen(scheme, &mut rng(1)).unwrap();

            for (origin, (sk, pk)) in [("graviola", from_graviola), ("rustcrypto", from_rustcrypto)] {
                let context = format!("{scheme:?}, key generated by {origin}");
                let signature = sign(scheme, &sk, &pk);

                assert_eq!(graviola::validate_signature_key(scheme, &pk), Ok(()), "{context}");
                assert_eq!(rustcrypto::validate_signature_key(scheme, &pk), Ok(()), "{context}");

                assert_eq!(
                    graviola::verify_signature(scheme, MESSAGE, &pk, &signature),
                    Ok(()),
                    "{context}: graviola verifies"
                );
                assert_eq!(
                    rustcrypto::verify_signature(scheme, MESSAGE, &pk, &signature),
                    Ok(()),
                    "{context}: rustcrypto verifies"
                );
            }
        }
    }

    #[test]
    fn signature_checks_reject_bad_input_identically() {
        if !both_backends_available() {
            return;
        }
        for scheme in SCHEMES {
            let (sk, pk) = rustcrypto::signature_key_gen(scheme, &mut rng(2)).unwrap();
            let signature = sign(scheme, &sk, &pk);
            let (_, other_pk) = rustcrypto::signature_key_gen(scheme, &mut rng(3)).unwrap();

            let mut flipped = signature.clone();
            *flipped.last_mut().unwrap() ^= 1;

            let cases: [VerifyCase; 6] = [
                ("wrong message", b"another message", &pk, &signature),
                ("wrong key", MESSAGE, &other_pk, &signature),
                ("flipped signature bit", MESSAGE, &pk, &flipped),
                ("empty signature", MESSAGE, &pk, &[]),
                ("truncated key", MESSAGE, &pk[..pk.len() - 1], &signature),
                ("empty key", MESSAGE, &[], &signature),
            ];
            for (case, message, pk, signature) in cases {
                let expected = rustcrypto::verify_signature(scheme, message, pk, signature);
                assert!(expected.is_err(), "{scheme:?}, {case}: rustcrypto must reject this");
                assert_eq!(
                    graviola::verify_signature(scheme, message, pk, signature),
                    expected,
                    "{scheme:?}, {case}: verify"
                );
            }

            for (case, key) in [("truncated key", &pk[..pk.len() - 1]), ("empty key", &[][..])] {
                let expected = rustcrypto::validate_signature_key(scheme, key);
                assert_eq!(expected, Err(CryptoError::InvalidKey), "{scheme:?}, {case}: rustcrypto");
                assert_eq!(
                    graviola::validate_signature_key(scheme, key),
                    expected,
                    "{scheme:?}, {case}: validate"
                );
            }
        }
    }

    #[test]
    fn unsupported_signature_scheme_is_rejected_identically() {
        if !both_backends_available() {
            return;
        }
        let scheme = SignatureScheme::ED448;
        assert_eq!(
            graviola::signature_key_gen(scheme, &mut rng(4)),
            rustcrypto::signature_key_gen(scheme, &mut rng(4))
        );
        assert_eq!(
            graviola::validate_signature_key(scheme, &[0; 57]),
            rustcrypto::validate_signature_key(scheme, &[0; 57])
        );
        assert_eq!(
            graviola::verify_signature(scheme, MESSAGE, &[0; 57], &[0; 114]),
            rustcrypto::verify_signature(scheme, MESSAGE, &[0; 57], &[0; 114])
        );
    }
}
