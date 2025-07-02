#![doc = include_str!("../README.md")]

pub use core_crypto_keystore::{Connection as CryptoKeystore, DatabaseKey};

mod crypto_provider;
mod error;
mod pki;

pub use error::{MlsProviderError, MlsProviderResult};

pub use crypto_provider::RustCrypto;

pub use pki::{CertProfile, CertificateGenerationArgs, PkiKeypair};
use typed_builder::TypedBuilder;

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

// we don't want to document this type; it's purely an implementation detail
// people get the builder from `MlsCryptoProvider::builder`, and the builder produces
// a `MlsCryptoProvider`
#[doc(hidden)]
#[derive(TypedBuilder)]
#[builder(build_method(into = MlsCryptoProvider))]
pub struct MlsCryptoProviderConfiguration {
    key_store: CryptoKeystore,
    /// External seed for the ChaCha20 PRNG entropy pool
    #[builder(default, setter(strip_option(fallback=entropy_seed_opt)))]
    entropy_seed: Option<EntropySeed>,
}

#[derive(Debug, Clone)]
pub struct MlsCryptoProvider {
    crypto: RustCrypto,
    key_store: CryptoKeystore,
    pki_env: PkiEnvironmentProvider,
}

impl From<MlsCryptoProviderConfiguration> for MlsCryptoProvider {
    fn from(
        MlsCryptoProviderConfiguration {
            key_store,
            entropy_seed,
        }: MlsCryptoProviderConfiguration,
    ) -> Self {
        let crypto = entropy_seed.map(RustCrypto::new_with_seed).unwrap_or_default();
        let pki_env = PkiEnvironmentProvider::default();

        Self {
            crypto,
            key_store,
            pki_env,
        }
    }
}

impl MlsCryptoProvider {
    /// Construct a builder which can build a crypto provider.
    ///
    /// See also:
    ///
    /// - [CryptoKeystore::open]
    pub fn builder() -> MlsCryptoProviderConfigurationBuilder {
        MlsCryptoProviderConfiguration::builder()
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

    /// Returns whether or not it is currently possible to close this provider.
    ///
    /// Reasons why it may not currently be possible:
    ///
    /// - A transaction is currently in progress
    /// - Multiple strong references currently exist to the keystore
    ///
    /// As with all such checks, this is vulnerable to TOCTOU issues, but as the current implementation
    /// of the [`MlsCryptoProvider::close`] function consumes `self`, this is the only way to check in advance whether
    /// this will in principle work.
    pub async fn can_close(&self) -> bool {
        self.key_store.can_close().await
    }

    /// Closes this provider, which in turns tears down the backing store
    ///
    /// Note: This does **not** destroy the data on-disk in case of persistent backing store
    pub async fn close(self) -> MlsProviderResult<()> {
        self.key_store.close().await.map_err(Into::into)
    }

    /// Clone keystore (its an `Arc` internnaly)
    pub fn keystore(&self) -> CryptoKeystore {
        self.key_store.clone()
    }

    /// Allows to retrieve the underlying key store directly
    pub fn unwrap_keystore(self) -> CryptoKeystore {
        self.key_store
    }
}

impl openmls_traits::OpenMlsCryptoProvider for MlsCryptoProvider {
    type CryptoProvider = RustCrypto;
    type RandProvider = RustCrypto;
    type KeyStoreProvider = CryptoKeystore;
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
