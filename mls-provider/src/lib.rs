#![doc = include_str!("../README.md")]

pub use core_crypto_keystore::{Database, DatabaseKey};

mod crypto_provider;
mod error;
mod pki;

pub use crypto_provider::RustCrypto;
pub use error::{MlsProviderError, MlsProviderResult};
use openmls_traits::{
    crypto::OpenMlsCrypto,
    types::{
        AeadType, Ciphersuite, CryptoError, ExporterSecret, HashType, HpkeCiphertext, HpkeConfig, HpkeKeyPair,
        KemOutput, SignatureScheme,
    },
};
pub use pki::{CertProfile, CertificateGenerationArgs, PkiKeypair};

use crate::pki::PkiEnvironmentProvider;

pub mod reexports {
    pub use rand_core;
}

/// 32-byte raw entropy seed
pub type RawEntropySeed = <rand_chacha::ChaCha20Rng as rand::SeedableRng>::Seed;

#[derive(Debug, Clone, Default, PartialEq, Eq, zeroize::ZeroizeOnDrop)]
#[repr(transparent)]
/// Wrapped 32-byte entropy seed with bounds check
pub struct EntropySeed(RawEntropySeed);

impl EntropySeed {
    pub const EXPECTED_LEN: usize = std::mem::size_of::<EntropySeed>() / std::mem::size_of::<u8>();

    pub fn try_from_slice(data: &[u8]) -> MlsProviderResult<Self> {
        if data.len() < Self::EXPECTED_LEN {
            return Err(MlsProviderError::EntropySeedLengthError {
                actual: data.len(),
                expected: Self::EXPECTED_LEN,
            });
        }

        let mut inner = RawEntropySeed::default();
        inner.copy_from_slice(&data[..Self::EXPECTED_LEN]);

        Ok(Self(inner))
    }

    pub fn from_raw(raw: RawEntropySeed) -> Self {
        Self(raw)
    }
}

impl std::ops::Deref for EntropySeed {
    type Target = [u8];
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl std::ops::DerefMut for EntropySeed {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

#[derive(Debug, Clone)]
pub struct MlsCryptoProvider {
    crypto: RustCrypto,
    key_store: Database,
    pki_env: PkiEnvironmentProvider,
}

impl MlsCryptoProvider {
    /// Construct a crypto provider with defaults and a given [Database].
    ///
    /// See also:
    ///
    /// - [Database::open]
    pub fn new(key_store: Database) -> Self {
        Self {
            key_store,
            crypto: Default::default(),
            pki_env: Default::default(),
        }
    }

    /// Clones the references of the PkiEnvironment and the CryptoProvider into a transaction
    /// keystore to pass to openmls as the `OpenMlsCryptoProvider`
    pub async fn new_transaction(&self) -> MlsProviderResult<()> {
        self.key_store.new_transaction().await.map_err(Into::into)
    }

    /// Replaces the PKI env currently in place
    pub async fn update_pki_env(
        &self,
        pki_env: wire_e2e_identity::prelude::x509::revocation::PkiEnvironment,
    ) -> MlsProviderResult<()> {
        self.pki_env.update_env(pki_env).await
    }

    /// Set pki_env to a new shared pki environment provider
    pub async fn set_pki_environment_provider(&mut self, pki_env: PkiEnvironmentProvider) {
        self.pki_env = pki_env;
    }

    /// Returns whether we have a PKI env setup
    pub async fn is_pki_env_setup(&self) -> bool {
        self.pki_env.is_env_setup().await
    }

    /// Reseeds the internal CSPRNG entropy pool with a brand new one.
    ///
    /// If [None] is provided, the new entropy will be pulled through the current OS target's capabilities
    pub fn reseed(&self, entropy_seed: Option<EntropySeed>) -> MlsProviderResult<()> {
        self.crypto.reseed(entropy_seed)
    }

    /// Wait for any keystore transaction to finish, then close the database connection.
    ///
    /// Note: This does **not** destroy the data on-disk in case of persistent backing store
    pub async fn close(&self) -> MlsProviderResult<()> {
        self.key_store.close().await?;
        Ok(())
    }

    /// Clone keystore (its an `Arc` internnaly)
    pub fn keystore(&self) -> Database {
        self.key_store.clone()
    }

    /// Allows to retrieve the underlying key store directly
    pub fn unwrap_keystore(self) -> Database {
        self.key_store
    }
}

impl openmls_traits::OpenMlsCryptoProvider for MlsCryptoProvider {
    type CryptoProvider = RustCrypto;
    type RandProvider = RustCrypto;
    type KeyStoreProvider = Database;
    type AuthenticationServiceProvider = PkiEnvironmentProvider;

    fn crypto(&self) -> &Self::CryptoProvider {
        &self.crypto
    }

    fn rand(&self) -> &Self::RandProvider {
        &self.crypto
    }

    fn key_store(&self) -> &Self::KeyStoreProvider {
        &self.key_store
    }

    fn authentication_service(&self) -> &Self::AuthenticationServiceProvider {
        &self.pki_env
    }
}

/// Passthrough implementation of crypto functionality for references to `MlsCryptoProvider`.
impl OpenMlsCrypto for &MlsCryptoProvider {
    fn supports(&self, ciphersuite: Ciphersuite) -> Result<(), CryptoError> {
        self.crypto.supports(ciphersuite)
    }

    fn supported_ciphersuites(&self) -> Vec<Ciphersuite> {
        self.crypto.supported_ciphersuites()
    }

    fn hkdf_extract(
        &self,
        hash_type: HashType,
        salt: &[u8],
        ikm: &[u8],
    ) -> Result<tls_codec::SecretVLBytes, CryptoError> {
        self.crypto.hkdf_extract(hash_type, salt, ikm)
    }

    fn hkdf_expand(
        &self,
        hash_type: HashType,
        prk: &[u8],
        info: &[u8],
        okm_len: usize,
    ) -> Result<tls_codec::SecretVLBytes, CryptoError> {
        self.crypto.hkdf_expand(hash_type, prk, info, okm_len)
    }

    fn hash(&self, hash_type: HashType, data: &[u8]) -> Result<Vec<u8>, CryptoError> {
        self.crypto.hash(hash_type, data)
    }

    fn aead_encrypt(
        &self,
        alg: AeadType,
        key: &[u8],
        data: &[u8],
        nonce: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        self.crypto.aead_encrypt(alg, key, data, nonce, aad)
    }

    fn aead_decrypt(
        &self,
        alg: AeadType,
        key: &[u8],
        ct_tag: &[u8],
        nonce: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        self.crypto.aead_decrypt(alg, key, ct_tag, nonce, aad)
    }

    fn signature_key_gen(&self, alg: SignatureScheme) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
        self.crypto.signature_key_gen(alg)
    }

    fn signature_public_key_len(&self, alg: SignatureScheme) -> usize {
        self.crypto.signature_public_key_len(alg)
    }

    fn validate_signature_key(&self, alg: SignatureScheme, key: &[u8]) -> Result<(), CryptoError> {
        self.crypto.validate_signature_key(alg, key)
    }

    fn verify_signature(
        &self,
        alg: SignatureScheme,
        data: &[u8],
        pk: &[u8],
        signature: &[u8],
    ) -> Result<(), CryptoError> {
        self.crypto.verify_signature(alg, data, pk, signature)
    }

    fn sign(&self, alg: SignatureScheme, data: &[u8], key: &[u8]) -> Result<Vec<u8>, CryptoError> {
        self.crypto.sign(alg, data, key)
    }

    fn hpke_seal(
        &self,
        config: HpkeConfig,
        pk_r: &[u8],
        info: &[u8],
        aad: &[u8],
        ptxt: &[u8],
    ) -> Result<HpkeCiphertext, CryptoError> {
        self.crypto.hpke_seal(config, pk_r, info, aad, ptxt)
    }

    fn hpke_open(
        &self,
        config: HpkeConfig,
        input: &HpkeCiphertext,
        sk_r: &[u8],
        info: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        self.crypto.hpke_open(config, input, sk_r, info, aad)
    }

    fn hpke_setup_sender_and_export(
        &self,
        config: HpkeConfig,
        pk_r: &[u8],
        info: &[u8],
        exporter_context: &[u8],
        exporter_length: usize,
    ) -> Result<(KemOutput, ExporterSecret), CryptoError> {
        self.crypto
            .hpke_setup_sender_and_export(config, pk_r, info, exporter_context, exporter_length)
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
        self.crypto
            .hpke_setup_receiver_and_export(config, enc, sk_r, info, exporter_context, exporter_length)
    }

    fn derive_hpke_keypair(&self, config: HpkeConfig, ikm: &[u8]) -> Result<HpkeKeyPair, CryptoError> {
        self.crypto.derive_hpke_keypair(config, ikm)
    }
}
