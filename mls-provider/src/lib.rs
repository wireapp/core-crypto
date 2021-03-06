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

use core_crypto_keystore::Connection as CryptoKeystore;

mod crypto_provider;
mod error;

pub use error::{MlsProviderError, MlsProviderResult};

pub use crypto_provider::RustCrypto;

pub type RawEntropySeed = <rand_chacha::ChaCha20Rng as rand::SeedableRng>::Seed;

#[derive(Debug, Clone, Default, PartialEq, Eq, zeroize::ZeroizeOnDrop)]
#[repr(transparent)]
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

#[derive(Debug, Clone, PartialEq)]
pub struct MlsCryptoProviderConfiguration<'a> {
    pub db_path: &'a str,
    pub identity_key: &'a str,
    pub in_memory: bool,
    /// External seed for the ChaCha20 PRNG entropy pool
    pub entropy_seed: Option<EntropySeed>,
}

#[derive(Debug)]
pub struct MlsCryptoProvider {
    crypto: RustCrypto,
    key_store: CryptoKeystore,
}

impl MlsCryptoProvider {
    pub async fn try_new_with_configuration(config: MlsCryptoProviderConfiguration<'_>) -> MlsProviderResult<Self> {
        let crypto = config.entropy_seed.map(RustCrypto::new_with_seed).unwrap_or_default();
        let key_store = if config.in_memory {
            CryptoKeystore::open_in_memory_with_key("", config.identity_key).await?
        } else {
            CryptoKeystore::open_with_key(config.db_path, config.identity_key).await?
        };
        Ok(Self { crypto, key_store })
    }

    pub async fn try_new(db_path: impl AsRef<str>, identity_key: impl AsRef<str>) -> MlsProviderResult<Self> {
        let crypto = RustCrypto::default();
        let key_store = CryptoKeystore::open_with_key(db_path, identity_key.as_ref()).await?;
        Ok(Self { crypto, key_store })
    }

    pub async fn try_new_in_memory(identity_key: impl AsRef<str>) -> MlsProviderResult<Self> {
        let crypto = RustCrypto::default();
        let key_store = CryptoKeystore::open_in_memory_with_key("", identity_key.as_ref()).await?;
        Ok(Self { crypto, key_store })
    }

    pub fn new_with_store(key_store: CryptoKeystore, entropy_seed: Option<EntropySeed>) -> Self {
        let crypto = entropy_seed.map(RustCrypto::new_with_seed).unwrap_or_default();
        Self { crypto, key_store }
    }

    pub fn reseed(&mut self, entropy_seed: Option<EntropySeed>) {
        self.crypto = entropy_seed.map(RustCrypto::new_with_seed).unwrap_or_default();
    }

    pub async fn close(self) -> MlsProviderResult<()> {
        Ok(self.key_store.close().await?)
    }

    pub async fn destroy_and_reset(self) -> MlsProviderResult<()> {
        Ok(self.key_store.wipe().await?)
    }

    pub fn unwrap_keystore(self) -> CryptoKeystore {
        self.key_store
    }
}

impl openmls_traits::OpenMlsCryptoProvider for MlsCryptoProvider {
    type CryptoProvider = RustCrypto;
    type RandProvider = RustCrypto;
    type KeyStoreProvider = CryptoKeystore;

    fn crypto(&self) -> &Self::CryptoProvider {
        &self.crypto
    }

    fn rand(&self) -> &Self::RandProvider {
        &self.crypto
    }

    fn key_store(&self) -> &Self::KeyStoreProvider {
        &self.key_store
    }
}
