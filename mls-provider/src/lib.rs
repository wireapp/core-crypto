#![doc = include_str!("../README.md")]

pub use core_crypto_keystore::{Database, DatabaseKey};

mod crypto_provider;
mod error;
mod pki;

pub use error::{MlsProviderError, MlsProviderResult};

pub use crypto_provider::RustCrypto;

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
    pub async fn close(self) -> MlsProviderResult<()> {
        self.key_store.close().await.map_err(Into::into)
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
