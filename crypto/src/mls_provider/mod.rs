// TODO: remove this expect(unreachable_pub) once the E2EI parts have been coupled.
#![expect(unreachable_pub)]
use std::sync::Arc;

use async_lock::RwLock;
pub use core_crypto_keystore::{Database, DatabaseKey};

mod crypto_provider;
mod error;

pub(crate) use crypto_provider::CRYPTO;
pub use crypto_provider::RustCrypto;
pub use error::{MlsProviderError, MlsProviderResult};
use openmls_traits::{
    authentication_service::{CredentialAuthenticationStatus, CredentialRef},
    crypto::OpenMlsCrypto,
    types::{
        AeadType, Ciphersuite, CryptoError, ExporterSecret, HashType, HpkeCiphertext, HpkeConfig, HpkeKeyPair,
        KemOutput, SignatureScheme,
    },
};
// TODO: remove this allow(unused) once the E2EI parts have been coupled.
#[allow(unused)]
pub use wire_e2e_identity::pki::{CertProfile, CertificateGenerationArgs, PkiKeypair};
use wire_e2e_identity::pki_env::PkiEnvironment;

/// 32-byte raw entropy seed
pub type RawEntropySeed = <rand_chacha::ChaCha20Rng as rand::SeedableRng>::Seed;

#[derive(Debug, Clone, Default, PartialEq, Eq, zeroize::ZeroizeOnDrop)]
#[repr(transparent)]
/// Wrapped 32-byte entropy seed with bounds check
pub struct EntropySeed(RawEntropySeed);

impl EntropySeed {
    /// The expected length of the entopy seed, in bytes.
    pub const EXPECTED_LEN: usize = std::mem::size_of::<EntropySeed>() / std::mem::size_of::<u8>();

    /// Create an entropy seed from the provided slice.
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

    /// Create an entropy seed from the provided raw entropy seed.
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

#[derive(Debug)]
pub struct AuthenticationService {
    /// The PKI Environment type is complicated, but it's all necessary:
    ///
    /// - The inner `Arc` derives from two facts: the PKI environment is provided across FFI, and it's `!Clone`,
    ///   so we have to retain that `Arc` because the foreign environment is more-or-less guaranteed to have
    ///   kept a reference to it.
    /// - The `Option` is there because the PKI environment is initially unset and may never be set,
    ///   according to client behavior.
    /// - The `RwLock` is there because we need to be able to set the PKI environment, implying interior mutability.
    pki_env: RwLock<Option<Arc<PkiEnvironment>>>,
}

impl AuthenticationService {
    pub async fn pki_env(&self) -> Option<Arc<PkiEnvironment>> {
        self.pki_env.read().await.clone()
    }
}

#[cfg_attr(target_os = "unknown", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_os = "unknown"), async_trait::async_trait)]
impl openmls_traits::authentication_service::AuthenticationServiceDelegate for AuthenticationService {
    async fn validate_credential<'a>(&'a self, credential: CredentialRef<'a>) -> CredentialAuthenticationStatus {
        match credential {
            // We assume that Basic credentials are always valid
            CredentialRef::Basic { .. } => CredentialAuthenticationStatus::Valid,

            CredentialRef::X509 { .. } => match self.pki_env.read().await.as_ref() {
                None => {
                    log::warn!("unable to validate X509 credentials: PKI environment is unset");
                    CredentialAuthenticationStatus::Unknown
                }
                Some(pki_env) => pki_env.validate_credential(credential).await,
            },
        }
    }
}

/// The MLS crypto provider
#[derive(Debug, Clone)]
pub struct MlsCryptoProvider {
    crypto: Arc<RustCrypto>,
    key_store: Database,
    auth_service: Arc<AuthenticationService>,
}

impl MlsCryptoProvider {
    /// Construct a crypto provider with defaults and a given [Database].
    ///
    /// See also:
    ///
    /// - [Database::open]
    pub fn new(key_store: Database) -> Self {
        Self::new_with_pki_env(key_store, None)
    }

    /// Construct a crypto provider with the given database and the PKI environment.
    pub fn new_with_pki_env(key_store: Database, pki_env: Option<Arc<PkiEnvironment>>) -> Self {
        let pki_env = RwLock::new(pki_env);
        let auth_service = Arc::new(AuthenticationService { pki_env });
        Self {
            key_store,
            crypto: Arc::clone(&CRYPTO),
            auth_service,
        }
    }

    /// Clones the references of the PkiEnvironment and the CryptoProvider into a transaction
    /// keystore to pass to openmls as the `OpenMlsCryptoProvider`
    pub async fn new_transaction(&self) -> MlsProviderResult<()> {
        self.key_store.new_transaction().await.map_err(Into::into)
    }

    /// Set pki_env to a new shared pki environment provider
    pub async fn set_pki_environment(&mut self, pki_env: Option<Arc<PkiEnvironment>>) {
        *self.auth_service.pki_env.write().await = pki_env;
    }

    /// Returns whether we have a PKI env setup
    pub async fn is_pki_env_setup(&self) -> bool {
        self.auth_service.pki_env.read().await.is_some()
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
}

impl openmls_traits::OpenMlsCryptoProvider for MlsCryptoProvider {
    type CryptoProvider = RustCrypto;
    type RandProvider = RustCrypto;
    type KeyStoreProvider = Database;
    type AuthenticationServiceProvider = AuthenticationService;

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
        &self.auth_service
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
