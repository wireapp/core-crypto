// Wire
// Copyright (C) 2022 Wire Swiss GmbH

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with this program. If not, see http://www.gnu.org/licenses/.

#![doc = include_str!("../README.md")]

pub use core_crypto_keystore::Connection as CryptoKeystore;

mod crypto_provider;
mod error;
mod pki;

use core_crypto_keystore::KeystoreTransaction;
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MlsCryptoProviderConfiguration<'a> {
    /// File path or database name of the persistent storage
    pub db_path: &'a str,
    /// Encryption master key of the encrypted-at-rest persistent storage
    pub identity_key: &'a str,
    /// Dictates whether or not the backend storage is in memory or not
    pub in_memory: bool,
    /// External seed for the ChaCha20 PRNG entropy pool
    pub entropy_seed: Option<EntropySeed>,
}

#[derive(Debug, Clone)]
pub struct MlsCryptoProvider {
    crypto: RustCrypto,
    key_store: CryptoKeystore,
    pki_env: PkiEnvironmentProvider,
}
pub type  TransactionalCryptoProvider = MlsCryptoProvider;

impl MlsCryptoProvider {
    /// Initialize a CryptoProvider with a backend following the provided `config` (see: [MlsCryptoProviderConfiguration])
    pub async fn try_new_with_configuration(config: MlsCryptoProviderConfiguration<'_>) -> MlsProviderResult<Self> {
        let crypto = config.entropy_seed.map(RustCrypto::new_with_seed).unwrap_or_default();
        let key_store = if config.in_memory {
            CryptoKeystore::open_in_memory_with_key("", config.identity_key).await?
        } else {
            CryptoKeystore::open_with_key(config.db_path, config.identity_key).await?
        };
        Ok(Self {
            crypto,
            key_store,
            pki_env: PkiEnvironmentProvider::default(),
        })
    }

    pub async fn try_new(db_path: impl AsRef<str>, identity_key: impl AsRef<str>) -> MlsProviderResult<Self> {
        let crypto = RustCrypto::default();
        let key_store = CryptoKeystore::open_with_key(db_path, identity_key.as_ref()).await?;
        Ok(Self {
            crypto,
            key_store,
            pki_env: PkiEnvironmentProvider::default(),
        })
    }

    pub async fn try_new_in_memory(identity_key: impl AsRef<str>) -> MlsProviderResult<Self> {
        let crypto = RustCrypto::default();
        let key_store = CryptoKeystore::open_in_memory_with_key("", identity_key.as_ref()).await?;
        Ok(Self {
            crypto,
            key_store,
            pki_env: PkiEnvironmentProvider::default(),
        })
    }

    /// Initialize a CryptoProvided with an already-configured backing store
    pub fn new_with_store(key_store: CryptoKeystore, entropy_seed: Option<EntropySeed>) -> Self {
        let crypto = entropy_seed.map(RustCrypto::new_with_seed).unwrap_or_default();
        Self {
            crypto,
            key_store,
            pki_env: PkiEnvironmentProvider::default(),
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

    /// Closes this provider, which in turns tears down the backing store
    ///
    /// Note: This does **not** destroy the data on-disk in case of persistent backing store
    pub async fn close(self) -> MlsProviderResult<()> {
        Ok(self.key_store.close().await?)
    }

    /// Tears down this provider and **obliterates every single piece of data stored on disk**.
    ///
    /// *you have been warned*
    pub async fn destroy_and_reset(self) -> MlsProviderResult<()> {
        Ok(self.key_store.wipe().await?)
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
