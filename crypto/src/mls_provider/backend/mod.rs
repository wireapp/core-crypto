//! Implementations of the primitives, chosen at build time.
//!
//! [`aws_lc`] is the backend everywhere but the browser, where aws-lc cannot be built.
//! [`rustcrypto`] is always compiled: it is the backend in the browser, and where aws-lc-rs has
//! nothing to offer, [`aws_lc`] delegates to it.

use openmls_traits::types::{
    AeadType, CryptoError, HashType, HpkeCiphertext, HpkeConfig, HpkeKeyPair, SignatureScheme,
};
use tls_codec::SecretVLBytes;

#[cfg(not(target_os = "unknown"))]
mod aws_lc;
#[cfg_attr(
    all(not(test), target_os = "unknown"),
    expect(dead_code, reason = "only aws-lc uses the HPKE core")
)]
pub(crate) mod hpke;
mod rustcrypto;

/// Call `$f` on the backend for this build.
macro_rules! dispatch {
    ($f:ident($($arg:expr),* $(,)?)) => {{
        #[cfg(not(target_os = "unknown"))]
        let result = aws_lc::$f($($arg),*);
        #[cfg(target_os = "unknown")]
        let result = rustcrypto::$f($($arg),*);
        result
    }};
}

pub(super) fn hash(hash_type: HashType, data: &[u8]) -> Result<Vec<u8>, CryptoError> {
    dispatch!(hash(hash_type, data))
}

pub(super) fn hkdf_extract(hash_type: HashType, salt: &[u8], ikm: &[u8]) -> Result<SecretVLBytes, CryptoError> {
    dispatch!(hkdf_extract(hash_type, salt, ikm))
}

pub(super) fn hkdf_expand(
    hash_type: HashType,
    prk: &[u8],
    info: &[u8],
    okm_len: usize,
) -> Result<SecretVLBytes, CryptoError> {
    dispatch!(hkdf_expand(hash_type, prk, info, okm_len))
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

pub(super) fn sign(alg: SignatureScheme, data: &[u8], key: &[u8]) -> Result<Vec<u8>, CryptoError> {
    dispatch!(sign(alg, data, key))
}

/// [`sign`], for when we also have the key pair's public key, which some backends can use.
pub(super) fn sign_with_public_key(
    alg: SignatureScheme,
    data: &[u8],
    key: &[u8],
    public_key: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    #[cfg(not(target_os = "unknown"))]
    let result = aws_lc::sign_with_public_key(alg, data, key, public_key);
    // rustcrypto has no use for the public key.
    #[cfg(target_os = "unknown")]
    let result = {
        let _ = public_key;
        rustcrypto::sign(alg, data, key)
    };
    result
}

pub(super) fn hpke_seal(
    config: &HpkeConfig,
    pk_r: &[u8],
    info: &[u8],
    aad: &[u8],
    psk: hpke::Psk<'_>,
    ptxt: &[u8],
    rng: &mut rand_chacha::ChaCha20Rng,
) -> Result<HpkeCiphertext, CryptoError> {
    dispatch!(hpke_seal(config, pk_r, info, aad, psk, ptxt, rng))
}

pub(super) fn hpke_open(
    config: &HpkeConfig,
    sk_r: &[u8],
    enc: &[u8],
    info: &[u8],
    aad: &[u8],
    psk: hpke::Psk<'_>,
    ciphertext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    dispatch!(hpke_open(config, sk_r, enc, info, aad, psk, ciphertext))
}

pub(super) fn hpke_export_tx(
    config: &HpkeConfig,
    pk_r: &[u8],
    info: &[u8],
    exporter_context: &[u8],
    len: usize,
    rng: &mut rand_chacha::ChaCha20Rng,
) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
    dispatch!(hpke_export_tx(config, pk_r, info, exporter_context, len, rng))
}

pub(super) fn hpke_export_rx(
    config: &HpkeConfig,
    enc: &[u8],
    sk_r: &[u8],
    info: &[u8],
    exporter_context: &[u8],
    len: usize,
) -> Result<Vec<u8>, CryptoError> {
    dispatch!(hpke_export_rx(config, enc, sk_r, info, exporter_context, len))
}

pub(super) fn hpke_derive_keypair(config: &HpkeConfig, ikm: &[u8]) -> Result<HpkeKeyPair, CryptoError> {
    dispatch!(hpke_derive_keypair(config, ikm))
}

/// aws-lc-rs and RustCrypto are interchangeable: the browser uses one and every other platform the
/// other, and a conversation spans both. So anything one produces the other must accept, and where
/// both reject an input they must agree on why. These tests hold that contract.
#[cfg(all(test, not(target_os = "unknown")))]
mod tests {
    use openmls_traits::types::{AeadType, CryptoError, HashType, SignatureScheme};
    use rand_core::SeedableRng as _;
    use signature::Signer as _;

    use super::{aws_lc, hpke, rustcrypto};

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
        let long = vec![0xa5; 10_000];
        for hash_type in [HashType::Sha2_256, HashType::Sha2_384, HashType::Sha2_512] {
            for data in [&[][..], b"abc", &long] {
                assert_eq!(
                    aws_lc::hash(hash_type, data),
                    rustcrypto::hash(hash_type, data),
                    "{hash_type:?} over {} bytes",
                    data.len()
                );
            }
        }
    }

    /// `(ikm, salt, info, prk, okm)`
    type HkdfVector = (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>);

    /// The SHA-256 test cases from RFC 5869, appendix A.
    fn rfc5869_vectors() -> [HkdfVector; 3] {
        let range = |r: std::ops::Range<u8>| r.collect::<Vec<u8>>();
        [
            (
                vec![0x0b; 22],
                range(0x00..0x0d),
                range(0xf0..0xfa),
                hex::decode("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5").unwrap(),
                hex::decode("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865")
                    .unwrap(),
            ),
            (
                range(0x00..0x50),
                range(0x60..0xb0),
                (0xb0..=0xff).collect(),
                hex::decode("06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244").unwrap(),
                hex::decode(
                    "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c\
                     59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71\
                     cc30c58179ec3e87c14c01d5c1f3434f1d87",
                )
                .unwrap(),
            ),
            (
                vec![0x0b; 22],
                Vec::new(),
                Vec::new(),
                hex::decode("19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04").unwrap(),
                hex::decode("8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8")
                    .unwrap(),
            ),
        ]
    }

    #[test]
    fn hkdf_matches_rfc5869_on_both_backends() {
        for (case, (ikm, salt, info, prk, okm)) in rfc5869_vectors().into_iter().enumerate() {
            for (backend, extract, expand) in [
                (
                    "aws-lc",
                    aws_lc::hkdf_extract as ExtractFn,
                    aws_lc::hkdf_expand as ExpandFn,
                ),
                ("rustcrypto", rustcrypto::hkdf_extract, rustcrypto::hkdf_expand),
            ] {
                let got_prk = extract(HashType::Sha2_256, &salt, &ikm).unwrap();
                assert_eq!(got_prk.as_slice(), prk, "{backend}, case {}: prk", case + 1);
                let got_okm = expand(HashType::Sha2_256, &prk, &info, okm.len()).unwrap();
                assert_eq!(got_okm.as_slice(), okm, "{backend}, case {}: okm", case + 1);
            }
        }
    }

    type ExtractFn = fn(HashType, &[u8], &[u8]) -> Result<tls_codec::SecretVLBytes, CryptoError>;
    type ExpandFn = fn(HashType, &[u8], &[u8], usize) -> Result<tls_codec::SecretVLBytes, CryptoError>;

    const HASHES: [(HashType, usize); 3] = [
        (HashType::Sha2_256, 32),
        (HashType::Sha2_384, 48),
        (HashType::Sha2_512, 64),
    ];

    #[test]
    fn hkdf_output_is_identical_on_both_backends() {
        let long = vec![0x5a; 300];
        for (hash_type, hash_len) in HASHES {
            for (salt, ikm) in [(&[][..], &b"ikm"[..]), (b"salt", &long), (&long, b"")] {
                assert_eq!(
                    aws_lc::hkdf_extract(hash_type, salt, ikm),
                    rustcrypto::hkdf_extract(hash_type, salt, ikm),
                    "{hash_type:?}: extract, salt {} bytes, ikm {} bytes",
                    salt.len(),
                    ikm.len()
                );
            }
            let prk = rustcrypto::hkdf_extract(hash_type, b"salt", b"ikm").unwrap();
            // A PRK longer than the block size is hashed down before keying HMAC.
            for prk in [prk.as_slice(), &long] {
                for okm_len in [
                    0,
                    1,
                    hash_len - 1,
                    hash_len,
                    hash_len + 1,
                    3 * hash_len + 7,
                    255 * hash_len,
                ] {
                    assert_eq!(
                        aws_lc::hkdf_expand(hash_type, prk, b"info", okm_len),
                        rustcrypto::hkdf_expand(hash_type, prk, b"info", okm_len),
                        "{hash_type:?}: expand {okm_len} bytes from a {}-byte prk",
                        prk.len()
                    );
                }
            }
        }
    }

    #[test]
    fn hkdf_expand_rejects_bad_input_identically() {
        for (hash_type, hash_len) in HASHES {
            let prk = vec![0x42; hash_len];
            for (case, prk, okm_len) in [
                ("short prk", &prk[..hash_len - 1], hash_len),
                ("empty prk", &[][..], hash_len),
                ("too much output", &prk[..], 255 * hash_len + 1),
            ] {
                let expected = rustcrypto::hkdf_expand(hash_type, prk, b"info", okm_len);
                assert_eq!(
                    expected,
                    Err(CryptoError::HkdfOutputLengthInvalid),
                    "{hash_type:?}, {case}: rustcrypto"
                );
                assert_eq!(
                    aws_lc::hkdf_expand(hash_type, prk, b"info", okm_len),
                    expected,
                    "{hash_type:?}, {case}"
                );
            }
        }
    }

    #[test]
    fn aead_output_is_identical_and_decrypts_on_either_backend() {
        let nonce = [7u8; 12];
        for (alg, key_len) in AEADS {
            let key = vec![0x42; key_len];
            for plaintext in [&[][..], b"x", &[0x5a; 1000]] {
                let from_aws_lc = aws_lc::aead_encrypt(alg, &key, plaintext, &nonce, b"aad").unwrap();
                let from_rustcrypto = rustcrypto::aead_encrypt(alg, &key, plaintext, &nonce, b"aad").unwrap();
                assert_eq!(from_aws_lc, from_rustcrypto, "{alg:?}: ciphertext and tag");

                assert_eq!(
                    aws_lc::aead_decrypt(alg, &key, &from_rustcrypto, &nonce, b"aad").as_deref(),
                    Ok(plaintext),
                    "{alg:?}: aws-lc decrypts rustcrypto output"
                );
                assert_eq!(
                    rustcrypto::aead_decrypt(alg, &key, &from_aws_lc, &nonce, b"aad").as_deref(),
                    Ok(plaintext),
                    "{alg:?}: rustcrypto decrypts aws-lc output"
                );
            }
        }
    }

    /// Malformed inputs must produce the same error whichever backend happens to be in use.
    #[test]
    fn aead_rejects_bad_input_identically() {
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
                    aws_lc::aead_decrypt(alg, key, ct, nonce, aad),
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
                    aws_lc::aead_encrypt(alg, key, b"plaintext", nonce, b"aad"),
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
        for scheme in SCHEMES {
            let from_aws_lc = aws_lc::signature_key_gen(scheme, &mut rng(1)).unwrap();
            let from_rustcrypto = rustcrypto::signature_key_gen(scheme, &mut rng(1)).unwrap();

            for (origin, (sk, pk)) in [("aws-lc", from_aws_lc), ("rustcrypto", from_rustcrypto)] {
                let context = format!("{scheme:?}, key generated by {origin}");
                let signature = sign(scheme, &sk, &pk);

                assert_eq!(aws_lc::validate_signature_key(scheme, &pk), Ok(()), "{context}");
                assert_eq!(rustcrypto::validate_signature_key(scheme, &pk), Ok(()), "{context}");

                assert_eq!(
                    aws_lc::verify_signature(scheme, MESSAGE, &pk, &signature),
                    Ok(()),
                    "{context}: aws-lc verifies"
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
                    aws_lc::verify_signature(scheme, message, pk, signature),
                    expected,
                    "{scheme:?}, {case}: verify"
                );
            }

            for (case, key) in [("truncated key", &pk[..pk.len() - 1]), ("empty key", &[][..])] {
                let expected = rustcrypto::validate_signature_key(scheme, key);
                assert_eq!(expected, Err(CryptoError::InvalidKey), "{scheme:?}, {case}: rustcrypto");
                assert_eq!(
                    aws_lc::validate_signature_key(scheme, key),
                    expected,
                    "{scheme:?}, {case}: validate"
                );
            }
        }
    }

    #[test]
    fn signatures_from_either_backend_verify_on_both() {
        for scheme in SCHEMES {
            let (sk, pk) = rustcrypto::signature_key_gen(scheme, &mut rng(5)).unwrap();
            let signatures = [
                ("aws-lc", aws_lc::sign(scheme, MESSAGE, &sk).unwrap()),
                (
                    "aws-lc with the public key",
                    aws_lc::sign_with_public_key(scheme, MESSAGE, &sk, &pk).unwrap(),
                ),
                ("rustcrypto", rustcrypto::sign(scheme, MESSAGE, &sk).unwrap()),
            ];
            for (origin, signature) in signatures {
                let context = format!("{scheme:?}, signed by {origin}");
                assert_eq!(
                    aws_lc::verify_signature(scheme, MESSAGE, &pk, &signature),
                    Ok(()),
                    "{context}: aws-lc verifies"
                );
                assert_eq!(
                    rustcrypto::verify_signature(scheme, MESSAGE, &pk, &signature),
                    Ok(()),
                    "{context}: rustcrypto verifies"
                );
            }
        }
    }

    const ECDSA_SCHEMES: [SignatureScheme; 3] = [
        SignatureScheme::ECDSA_SECP256R1_SHA256,
        SignatureScheme::ECDSA_SECP384R1_SHA384,
        SignatureScheme::ECDSA_SECP521R1_SHA512,
    ];

    /// `sign_with_public_key` falls back to signing without the public key whenever aws-lc
    /// rejects it, so a DER encoding aws-lc can't read would only make signing slow, not fail.
    /// Check that aws-lc reads ours, and that it rejects a public key from another pair, which
    /// is what the fallback is for.
    #[test]
    fn aws_lc_loads_ecdsa_keys_with_their_public_key() {
        for scheme in ECDSA_SCHEMES {
            let (sk, pk) = rustcrypto::signature_key_gen(scheme, &mut rng(9)).unwrap();
            let (_, other_pk) = rustcrypto::signature_key_gen(scheme, &mut rng(10)).unwrap();
            let signature = aws_lc::ecdsa_sign_with_public_key_for_tests(scheme, MESSAGE, &sk, &pk)
                .unwrap_or_else(|err| panic!("{scheme:?}: aws-lc rejected the key pair: {err:?}"));
            assert_eq!(
                rustcrypto::verify_signature(scheme, MESSAGE, &pk, &signature),
                Ok(()),
                "{scheme:?}"
            );
            assert_eq!(
                aws_lc::ecdsa_sign_with_public_key_for_tests(scheme, MESSAGE, &sk, &other_pk),
                Err(CryptoError::InvalidKey),
                "{scheme:?}, another pair's public key"
            );
        }
    }

    /// rustcrypto ignores the public key, so a wrong one must not change what aws-lc does either.
    #[test]
    fn signing_with_a_wrong_public_key_signs_as_without_it() {
        for scheme in SCHEMES {
            let (sk, pk) = rustcrypto::signature_key_gen(scheme, &mut rng(11)).unwrap();
            let (_, other_pk) = rustcrypto::signature_key_gen(scheme, &mut rng(12)).unwrap();
            let wrong_public_keys = [
                ("another pair's", other_pk.clone()),
                ("an empty", vec![]),
                ("a truncated", pk[..pk.len() - 1].to_vec()),
            ];
            for (case, wrong_pk) in wrong_public_keys {
                let signature = aws_lc::sign_with_public_key(scheme, MESSAGE, &sk, &wrong_pk)
                    .unwrap_or_else(|err| panic!("{scheme:?}, {case} public key: {err:?}"));
                assert_eq!(
                    rustcrypto::verify_signature(scheme, MESSAGE, &pk, &signature),
                    Ok(()),
                    "{scheme:?}, {case} public key"
                );
            }

            // A bad private key fails as it does without the public key.
            let long_sk = [&sk[..], &[0]].concat();
            let expected = rustcrypto::sign(scheme, MESSAGE, &long_sk);
            assert_eq!(expected, Err(CryptoError::InvalidKey), "{scheme:?}: rustcrypto");
            assert_eq!(
                aws_lc::sign_with_public_key(scheme, MESSAGE, &long_sk, &pk),
                expected,
                "{scheme:?}, long private key"
            );
        }
    }

    /// Keystores written by older versions hold Ed25519 private keys as `seed || public key`.
    #[test]
    fn legacy_ed25519_keypair_encoding_signs_on_both_backends() {
        let scheme = SignatureScheme::ED25519;
        let (seed, pk) = rustcrypto::signature_key_gen(scheme, &mut rng(6)).unwrap();
        let legacy = [&seed[..], &pk[..]].concat();
        let (_, other_pk) = rustcrypto::signature_key_gen(scheme, &mut rng(7)).unwrap();
        let mismatched = [&seed[..], &other_pk[..]].concat();

        // Ed25519 is deterministic, so a backend loading the key correctly reproduces the
        // signature made from the bare seed.
        let expected = rustcrypto::sign(scheme, MESSAGE, &seed).unwrap();
        assert_eq!(aws_lc::sign(scheme, MESSAGE, &legacy).as_ref(), Ok(&expected));
        assert_eq!(rustcrypto::sign(scheme, MESSAGE, &legacy).as_ref(), Ok(&expected));

        assert_eq!(
            rustcrypto::sign(scheme, MESSAGE, &mismatched),
            Err(CryptoError::InvalidKey)
        );
        assert_eq!(aws_lc::sign(scheme, MESSAGE, &mismatched), Err(CryptoError::InvalidKey));
    }

    #[test]
    fn signing_rejects_bad_keys_identically() {
        for scheme in SCHEMES {
            let (sk, _) = rustcrypto::signature_key_gen(scheme, &mut rng(8)).unwrap();
            let zero = vec![0; sk.len()];
            // A key a few bytes short is left out on purpose: RustCrypto's ECDSA `from_slice`
            // left-pads it with zeros and signs, while aws-lc rejects it. Our keys are always
            // full length, so only a corrupted key could tell the two apart.
            for (case, key) in [("empty key", &[][..]), ("long key", &[&sk[..], &[0]].concat())] {
                let expected = rustcrypto::sign(scheme, MESSAGE, key);
                assert_eq!(expected, Err(CryptoError::InvalidKey), "{scheme:?}, {case}: rustcrypto");
                assert_eq!(aws_lc::sign(scheme, MESSAGE, key), expected, "{scheme:?}, {case}");
            }
            // Zero is not a valid ECDSA scalar. (It is a valid Ed25519 seed.)
            if scheme != SignatureScheme::ED25519 {
                let expected = rustcrypto::sign(scheme, MESSAGE, &zero);
                assert_eq!(
                    expected,
                    Err(CryptoError::InvalidKey),
                    "{scheme:?}, zero scalar: rustcrypto"
                );
                assert_eq!(
                    aws_lc::sign(scheme, MESSAGE, &zero),
                    expected,
                    "{scheme:?}, zero scalar"
                );
            }
        }
    }

    #[test]
    fn hpke_on_aws_lc_matches_rfc9180_vectors() {
        hpke::tests::check_rfc9180_vectors::<aws_lc::AwsLc>(|_| true);
    }

    #[test]
    fn hpke_on_aws_lc_agrees_with_the_hpke_crate() {
        hpke::tests::check_agreement_with_the_hpke_crate::<aws_lc::AwsLc>(|_| true);
    }

    #[test]
    fn hpke_on_aws_lc_rejects_malformed_input() {
        hpke::tests::check_rejections::<aws_lc::AwsLc>(|_| true);
    }

    /// Through the backends' public HPKE functions: each backend opens what the other sealed,
    /// and both derive the same key pairs.
    #[test]
    fn hpke_is_interchangeable_between_backends() {
        let mut rng = rng(10);
        let psk = [0x77; 32];
        for config in hpke::tests::configs() {
            let aws_lc_keys = aws_lc::hpke_derive_keypair(&config, &[0x42; 64]).unwrap();
            let rustcrypto_keys = rustcrypto::hpke_derive_keypair(&config, &[0x42; 64]).unwrap();
            assert_eq!(
                &*aws_lc_keys.private, &*rustcrypto_keys.private,
                "{config:?}: private key"
            );
            assert_eq!(aws_lc_keys.public, rustcrypto_keys.public, "{config:?}: public key");
            let (sk, pk) = (&*aws_lc_keys.private, &aws_lc_keys.public[..]);

            for psk in [None, Some((&psk[..], &b"psk id"[..]))] {
                let from_aws_lc = aws_lc::hpke_seal(&config, pk, b"info", b"aad", psk, b"pt", &mut rng).unwrap();
                let from_rustcrypto =
                    rustcrypto::hpke_seal(&config, pk, b"info", b"aad", psk, b"pt", &mut rng).unwrap();
                for (opener, open, sealed) in [
                    ("rustcrypto", rustcrypto::hpke_open as HpkeOpenFn, &from_aws_lc),
                    ("aws-lc", aws_lc::hpke_open, &from_rustcrypto),
                ] {
                    assert_eq!(
                        open(
                            &config,
                            sk,
                            sealed.kem_output.as_slice(),
                            b"info",
                            b"aad",
                            psk,
                            sealed.ciphertext.as_slice()
                        ),
                        Ok(b"pt".to_vec()),
                        "{config:?}, psk: {}: {opener} opens",
                        psk.is_some()
                    );
                }
            }
        }
    }

    type HpkeOpenFn = fn(
        &openmls_traits::types::HpkeConfig,
        &[u8],
        &[u8],
        &[u8],
        &[u8],
        hpke::Psk<'_>,
        &[u8],
    ) -> Result<Vec<u8>, CryptoError>;

    #[test]
    fn unsupported_signature_scheme_is_rejected_identically() {
        let scheme = SignatureScheme::ED448;
        assert_eq!(
            aws_lc::signature_key_gen(scheme, &mut rng(4)),
            rustcrypto::signature_key_gen(scheme, &mut rng(4))
        );
        assert_eq!(
            aws_lc::validate_signature_key(scheme, &[0; 57]),
            rustcrypto::validate_signature_key(scheme, &[0; 57])
        );
        assert_eq!(
            aws_lc::verify_signature(scheme, MESSAGE, &[0; 57], &[0; 114]),
            rustcrypto::verify_signature(scheme, MESSAGE, &[0; 57], &[0; 114])
        );
        assert_eq!(
            aws_lc::sign(scheme, MESSAGE, &[0; 57]),
            rustcrypto::sign(scheme, MESSAGE, &[0; 57])
        );
    }

    /// rustcrypto verifies Ed25519 with dalek's `verify_strict`, which rejects signatures a less
    /// careful verifier accepts: under a small-order public key, where a forged `(R, S)` satisfies
    /// the verification equation for any message, and with a non-canonical `S`, which makes
    /// signatures malleable. aws-lc must reject them the same way.
    #[test]
    fn ed25519_rejects_weak_keys_and_malleable_signatures_identically() {
        let scheme = SignatureScheme::ED25519;
        let mut identity = [0u8; 32];
        identity[0] = 1;
        let order_2 = hex::decode("ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f").unwrap();
        let forged = [&identity[..], &[0u8; 32]].concat();

        let (sk, pk) = rustcrypto::signature_key_gen(scheme, &mut rng(11)).unwrap();
        let signature = rustcrypto::sign(scheme, MESSAGE, &sk).unwrap();
        let non_canonical_s = [&signature[..32], &add_group_order(&signature[32..])].concat();

        let cases: [VerifyCase; 3] = [
            ("identity public key, forged signature", MESSAGE, &identity, &forged),
            ("order-2 public key, forged signature", MESSAGE, &order_2, &forged),
            ("S plus the group order", MESSAGE, &pk, &non_canonical_s),
        ];
        // Collect every disagreement before failing, so one run shows all of them.
        let mut disagreements = Vec::new();
        for (case, message, pk, signature) in cases {
            let expected = rustcrypto::verify_signature(scheme, message, pk, signature);
            assert!(expected.is_err(), "{case}: rustcrypto must reject this");
            let got = aws_lc::verify_signature(scheme, message, pk, signature);
            if got != expected {
                disagreements.push(format!("verify, {case}: aws-lc {got:?}, rustcrypto {expected:?}"));
            }
        }
        for (case, pk) in [("identity", &identity[..]), ("order 2", &order_2)] {
            let expected = rustcrypto::validate_signature_key(scheme, pk);
            let got = aws_lc::validate_signature_key(scheme, pk);
            if got != expected {
                disagreements.push(format!("validate, {case}: aws-lc {got:?}, rustcrypto {expected:?}"));
            }
        }
        assert!(disagreements.is_empty(), "{disagreements:#?}");
    }

    /// Every encoding on the small-order list in `aws_lc`, with either sign bit, is one dalek
    /// also considers weak, and an ordinary key is not on it. That the list is complete rests on
    /// libsodium, where it comes from; the forged-signature cases above exercise it.
    #[test]
    fn ed25519_small_order_list_matches_dalek() {
        let mut weak = 0;
        for entry in small_order_list() {
            for sign in [0x00, 0x80] {
                let mut encoding = entry;
                encoding[31] |= sign;
                assert!(aws_lc::is_small_order_ed25519_for_tests(&encoding), "{encoding:02x?}");
                if let Ok(key) = ed25519_dalek::VerifyingKey::from_bytes(&encoding) {
                    assert!(key.is_weak(), "dalek: {encoding:02x?} is not weak");
                    weak += 1;
                }
            }
        }
        assert!(weak >= 8, "only {weak} of the listed encodings decode");

        let (_, pk) = rustcrypto::signature_key_gen(SignatureScheme::ED25519, &mut rng(12)).unwrap();
        assert!(
            !aws_lc::is_small_order_ed25519_for_tests(&pk),
            "an ordinary key is not on the list"
        );
    }

    /// The entries of the small-order list, in canonical form, as dalek sees them.
    fn small_order_list() -> Vec<[u8; 32]> {
        [
            "0000000000000000000000000000000000000000000000000000000000000000",
            "0100000000000000000000000000000000000000000000000000000000000000",
            "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
            "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
            "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
            "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
            "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        ]
        .iter()
        .map(|entry| hex::decode(entry).unwrap().try_into().unwrap())
        .collect()
    }

    /// `S + L`, little-endian, where `L` is the order of the Ed25519 base point. `S < L < 2^253`,
    /// so this does not overflow.
    fn add_group_order(s: &[u8]) -> [u8; 32] {
        let order = hex::decode("edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010").unwrap();
        let mut out = [0u8; 32];
        let mut carry = 0u16;
        for i in 0..32 {
            let sum = u16::from(s[i]) + u16::from(order[i]) + carry;
            out[i] = sum as u8;
            carry = sum >> 8;
        }
        out
    }

    /// `aws_lc::signature_key_gen` relies on aws-lc rejecting scalars outside `[1, n)` for its
    /// rejection sampling. Accepting a larger one would yield a private key rustcrypto refuses.
    #[test]
    fn ecdh_private_key_rejects_out_of_range_scalars() {
        use aws_lc_rs::agreement;
        let p521_order = concat!(
            "01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa",
            "51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386409"
        );
        for (alg, order) in [
            (
                &agreement::ECDH_P256,
                "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
            ),
            (
                &agreement::ECDH_P384,
                "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973",
            ),
            (&agreement::ECDH_P521, p521_order),
        ] {
            let order = hex::decode(order).unwrap();
            let mut below = order.clone();
            *below.last_mut().unwrap() -= 1;
            let mut above = order.clone();
            *above.last_mut().unwrap() += 1;
            let zero = vec![0u8; order.len()];
            let len = order.len();
            assert!(
                agreement::PrivateKey::from_private_key(alg, &below).is_ok(),
                "{len}: n - 1"
            );
            for (case, scalar) in [("zero", &zero), ("n", &order), ("n + 1", &above)] {
                assert!(
                    agreement::PrivateKey::from_private_key(alg, scalar).is_err(),
                    "{len}: {case}"
                );
            }
        }
    }
}
