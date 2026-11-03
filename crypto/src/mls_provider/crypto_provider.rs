use std::sync::{Arc, LazyLock, PoisonError, RwLock, RwLockWriteGuard};

use crypto_common::KeySizeUser as _;
use elliptic_curve::sec1;
use openmls::prelude::HpkeCiphertext;
use openmls_traits::{
    crypto::OpenMlsCrypto,
    random::OpenMlsRand,
    types::{self, AeadType, Ciphersuite, CryptoError, ExporterSecret, HashType, HpkeConfig, SignatureScheme},
};
use rand::Rng as _;
use rand_core::SeedableRng as _;
use signature::digest::typenum::Unsigned;
use tls_codec::SecretVLBytes;

use super::{EntropySeed, Error, RawEntropySeed, backend};

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

impl RustCrypto {
    pub(crate) fn new_with_seed(seed: EntropySeed) -> Self {
        Self {
            rng: Arc::new(rand_chacha::ChaCha20Rng::from_seed(seed.0).into()),
        }
    }

    /// Lock the RNG for writing.
    ///
    /// A poisoned lock means some thread panicked while holding the guard. That can happen in
    /// code that uses the RNG, such as a primitive that panics on a malformed input, but not in
    /// the RNG itself. The RNG is plain data with no invariant for such a panic to break, so we
    /// carry on and do not leave the provider unable to produce randomness for the rest of the
    /// process.
    fn rng(&self) -> RwLockWriteGuard<'_, rand_chacha::ChaCha20Rng> {
        self.rng.write().unwrap_or_else(PoisonError::into_inner)
    }

    pub(crate) fn reseed(&self, seed: Option<EntropySeed>) -> Result<(), Error> {
        let seed = seed.map(|seed| Ok(seed.0)).unwrap_or_else(|| {
            // Pull from the OS, as `Self::default` does. Note we cannot fall back to
            // `EntropySeed::default()` here: that is 32 zero bytes, i.e. a fixed and publicly
            // known key, and this generator is shared process-wide.
            let mut raw = RawEntropySeed::default();
            getrandom::fill(&mut raw).map_err(|_| Error::InsufficientEntropy)?;
            Ok(raw)
        })?;

        *self.rng() = rand_chacha::ChaCha20Rng::from_seed(seed);
        Ok(())
    }

    /// Sign `data` as [`OpenMlsCrypto::sign`] does, given the key pair's public key as well.
    ///
    /// Some backends sign faster when they don't have to derive the public key themselves.
    /// `public_key` should belong to `key`. If it doesn't, the signature is the one `sign` makes.
    pub(crate) fn sign_with_public_key(
        &self,
        alg: SignatureScheme,
        data: &[u8],
        key: &[u8],
        public_key: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        backend::sign_with_public_key(alg, data, key, public_key)
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
        validate_psk(psk, psk_id)?;
        let mut rng = self.rng();
        backend::hpke_seal(&config, pk_r, info, aad, Some((psk, psk_id)), ptxt, &mut rng)
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
        validate_psk(psk, psk_id)?;
        backend::hpke_open(
            &config,
            sk_r,
            input.kem_output.as_slice(),
            info,
            aad,
            Some((psk, psk_id)),
            input.ciphertext.as_slice(),
        )
    }
}

/// RFC 9180 section 5.1 requires that a PSK used in `mode_psk` or `mode_auth_psk` "MUST contain at
/// least 32 bytes of entropy", and that the PSK and its id are either both present or both absent.
///
/// `hpke::OpModeS::Psk` enforces only the latter: `PskBundle::new(&[], &[])` is accepted and is
/// documented as being "equivalent to `Base`".
fn validate_psk(psk: &[u8], psk_id: &[u8]) -> Result<(), CryptoError> {
    const MIN_PSK_LEN: usize = 32;

    if psk.len() < MIN_PSK_LEN || psk_id.is_empty() {
        return Err(CryptoError::InvalidLength);
    }
    Ok(())
}

impl OpenMlsCrypto for RustCrypto {
    // These lengths are fixed by the curve specifications, so we can return them
    // directly without consulting a backend.
    fn signature_public_key_len(&self, signature_scheme: SignatureScheme) -> usize {
        // `signature_key_gen` emits ECDSA public keys as uncompressed SEC1 points -- a 0x04 tag
        // byte followed by the two field elements -- so the serialized length is not the field
        // size. Returning the field size here makes the `OpenMlsCrypto::validate_signature_key`
        // default reject every key this provider produces.
        match signature_scheme {
            SignatureScheme::ECDSA_SECP256R1_SHA256 => sec1::Tag::Uncompressed
                .message_len(<p256::NistP256 as p256::elliptic_curve::Curve>::FieldBytesSize::to_usize()),
            SignatureScheme::ECDSA_SECP384R1_SHA384 => sec1::Tag::Uncompressed
                .message_len(<p384::NistP384 as p384::elliptic_curve::Curve>::FieldBytesSize::to_usize()),
            SignatureScheme::ECDSA_SECP521R1_SHA512 => sec1::Tag::Uncompressed
                .message_len(<p521::NistP521 as p521::elliptic_curve::Curve>::FieldBytesSize::to_usize()),
            SignatureScheme::ED25519 => ed25519_dalek::PUBLIC_KEY_LENGTH,
            SignatureScheme::ED448 => 57,
            SignatureScheme::MLDSA44 => ml_dsa::VerifyingKey::<ml_dsa::MlDsa44>::key_size(),
            SignatureScheme::MLDSA65 => ml_dsa::VerifyingKey::<ml_dsa::MlDsa65>::key_size(),
            SignatureScheme::MLDSA87 => ml_dsa::VerifyingKey::<ml_dsa::MlDsa87>::key_size(),
        }
    }

    fn supports(&self, cipher_suite: Ciphersuite) -> Result<(), CryptoError> {
        match cipher_suite {
            Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519
            | Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519
            | Ciphersuite::MLS_128_DHKEMP256_AES128GCM_SHA256_P256
            | Ciphersuite::MLS_256_DHKEMP384_AES256GCM_SHA384_P384
            | Ciphersuite::MLS_256_DHKEMP521_AES256GCM_SHA512_P521
            // PQ ciphersuites from draft-ietf-mls-pq-ciphersuites-06
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
            // PQ ciphersuites from draft-ietf-mls-pq-ciphersuites-06
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
        backend::hkdf_extract(hash_type, salt, ikm)
    }

    fn hkdf_expand(
        &self,
        hash_type: HashType,
        prk: &[u8],
        info: &[u8],
        okm_len: usize,
    ) -> Result<SecretVLBytes, CryptoError> {
        backend::hkdf_expand(hash_type, prk, info, okm_len)
    }

    fn hash(&self, hash_type: HashType, data: &[u8]) -> Result<Vec<u8>, CryptoError> {
        backend::hash(hash_type, data)
    }

    fn aead_encrypt(
        &self,
        alg: AeadType,
        key: &[u8],
        data: &[u8],
        nonce: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        backend::aead_encrypt(alg, key, data, nonce, aad)
    }

    fn aead_decrypt(
        &self,
        alg: AeadType,
        key: &[u8],
        ct_tag: &[u8],
        nonce: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        backend::aead_decrypt(alg, key, ct_tag, nonce, aad)
    }

    /// Generate a `(secret key, public key)` pair from a signature scheme.
    fn signature_key_gen(&self, alg: SignatureScheme) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
        let mut rng = self.rng();
        backend::signature_key_gen(alg, &mut rng)
    }

    fn validate_signature_key(&self, alg: SignatureScheme, key: &[u8]) -> Result<(), CryptoError> {
        backend::validate_signature_key(alg, key)
    }

    fn verify_signature(
        &self,
        alg: SignatureScheme,
        data: &[u8],
        pk: &[u8],
        signature: &[u8],
    ) -> Result<(), CryptoError> {
        backend::verify_signature(alg, data, pk, signature)
    }

    fn sign(&self, alg: SignatureScheme, data: &[u8], key: &[u8]) -> Result<Vec<u8>, CryptoError> {
        backend::sign(alg, data, key)
    }

    fn hpke_seal(
        &self,
        config: HpkeConfig,
        pk_r: &[u8],
        info: &[u8],
        aad: &[u8],
        ptxt: &[u8],
    ) -> Result<types::HpkeCiphertext, CryptoError> {
        let mut rng = self.rng();
        backend::hpke_seal(&config, pk_r, info, aad, None, ptxt, &mut rng)
    }

    fn hpke_open(
        &self,
        config: HpkeConfig,
        input: &types::HpkeCiphertext,
        sk_r: &[u8],
        info: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        backend::hpke_open(
            &config,
            sk_r,
            input.kem_output.as_slice(),
            info,
            aad,
            None,
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
        let mut rng = self.rng();
        let (kem_output, export) =
            backend::hpke_export_tx(&config, pk_r, info, exporter_context, exporter_length, &mut rng)?;

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
        let export = backend::hpke_export_rx(&config, enc, sk_r, info, exporter_context, exporter_length)?;

        debug_assert_eq!(export.len(), exporter_length);

        Ok(export.into())
    }

    fn derive_hpke_keypair(&self, config: HpkeConfig, ikm: &[u8]) -> Result<types::HpkeKeyPair, CryptoError> {
        backend::hpke_derive_keypair(&config, ikm)
    }
}

impl OpenMlsRand for RustCrypto {
    type Error = Error;

    type RandImpl = rand_chacha::ChaCha20Rng;
    type BorrowTarget<'a> = RwLockWriteGuard<'a, Self::RandImpl>;

    fn borrow_rand(&self) -> Result<Self::BorrowTarget<'_>, Self::Error> {
        Ok(self.rng())
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

#[cfg(test)]
mod tests {
    use openmls_traits::{
        crypto::OpenMlsCrypto as _,
        random::OpenMlsRand as _,
        types::{CryptoError, HpkeAeadType, HpkeCiphertext, HpkeConfig, HpkeKdfType, HpkeKemType, SignatureScheme},
    };

    use super::{EntropySeed, RawEntropySeed, RustCrypto};

    /// `signature_public_key_len` exists so that callers can size a buffer for, or validate the
    /// length of, a public key this provider produced. It is only meaningful if it agrees with
    /// what `signature_key_gen` actually emits.
    #[test]
    fn signature_public_key_len_matches_generated_keys() {
        let crypto = RustCrypto::default();

        for scheme in [
            SignatureScheme::ED25519,
            SignatureScheme::ECDSA_SECP256R1_SHA256,
            SignatureScheme::ECDSA_SECP384R1_SHA384,
            SignatureScheme::ECDSA_SECP521R1_SHA512,
        ] {
            let (_sk, pk) = crypto
                .signature_key_gen(scheme)
                .expect("this provider supports all four of these schemes");

            assert_eq!(
                pk.len(),
                crypto.signature_public_key_len(scheme),
                "reported public key length for {scheme:?} must match the generated key"
            );

            // The generated key must also pass this provider's own validation, which is what the
            // trait's default implementation would have used the length above to decide.
            crypto
                .validate_signature_key(scheme, &pk)
                .unwrap_or_else(|err| panic!("generated {scheme:?} key must validate: {err:?}"));
        }
    }

    /// An empty PSK provides no binding, and `hpke` treats such a bundle as plain `Base` mode, so
    /// the `_psk` entry points must not silently accept one.
    #[test]
    fn hpke_psk_mode_rejects_a_psk_without_entropy() {
        let crypto = RustCrypto::default();
        // `HpkeConfig` is neither `Copy` nor `Clone`, so build a fresh one per call.
        let config = || {
            HpkeConfig(
                HpkeKemType::DhKem25519,
                HpkeKdfType::HkdfSha256,
                HpkeAeadType::AesGcm128,
            )
        };
        // Deliberately not a real recipient key or ciphertext: the PSK is checked before any of
        // that is parsed, and asserting on `InvalidLength` specifically keeps this test from
        // passing for the wrong reason.
        let pk_r = [0u8; 32];
        let ciphertext = HpkeCiphertext {
            kem_output: Vec::new().into(),
            ciphertext: Vec::new().into(),
        };

        for (psk, psk_id, case) in [
            (&[][..], &[][..], "empty psk and psk id"),
            (&[0u8; 32][..], &[][..], "empty psk id"),
            (&[0u8; 31][..], &b"id"[..], "psk one byte short of 32"),
        ] {
            assert_eq!(
                crypto.hpke_seal_psk(config(), &pk_r, b"info", b"aad", psk, psk_id, b"ptxt"),
                Err(CryptoError::InvalidLength),
                "hpke_seal_psk must reject: {case}"
            );
            assert_eq!(
                crypto.hpke_open_psk(config(), &ciphertext, &pk_r, b"info", b"aad", psk, psk_id),
                Err(CryptoError::InvalidLength),
                "hpke_open_psk must reject: {case}"
            );
        }
    }

    /// Reseeding without a seed must take one from the OS.
    ///
    /// It previously fell back to `EntropySeed::default()`, i.e. 32 zero bytes, which made every
    /// subsequent key and nonce reproducible by anyone -- and for the whole process, since the
    /// generator is a shared singleton.
    #[test]
    fn reseeding_without_a_seed_does_not_use_a_fixed_key() {
        // Deliberately not the `CRYPTO` singleton: reseeding that would perturb other tests.
        let crypto = RustCrypto::default();

        crypto.reseed(None).unwrap();
        let first = crypto.random_vec(32).unwrap();

        crypto.reseed(None).unwrap();
        let second = crypto.random_vec(32).unwrap();

        assert_ne!(first, second, "two OS-seeded reseeds must not produce the same stream");

        crypto
            .reseed(Some(EntropySeed::from_raw(RawEntropySeed::default())))
            .unwrap();
        let all_zero_seed = crypto.random_vec(32).unwrap();

        assert_ne!(
            first, all_zero_seed,
            "an OS-seeded reseed must not produce the all-zero-seed stream"
        );
    }
    /// A panic while the RNG is borrowed poisons its lock. That must not leave the provider
    /// unable to produce randomness for the rest of the process: such a panic once made every
    /// later key generation fail with `InsufficientRandomness`.
    #[test]
    #[cfg(not(target_os = "unknown"))]
    fn a_panic_while_the_rng_is_borrowed_does_not_disable_it() {
        let crypto = RustCrypto::default();

        let panicked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _rng = crypto.rng();
            panic!("deliberate panic while holding the RNG lock");
        }));
        assert!(panicked.is_err());
        assert!(crypto.rng.is_poisoned(), "precondition: the lock is poisoned");

        assert_eq!(crypto.random_vec(32).expect("random_vec").len(), 32);
        crypto
            .signature_key_gen(SignatureScheme::ED25519)
            .expect("key generation must still work");
        crypto.reseed(None).expect("reseed must still work");
    }
}
