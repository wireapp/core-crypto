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

use core_crypto_keystore::{Connection as CryptoKeystore, CryptoKeystoreResult};
use openmls_rust_crypto::RustCrypto;

#[derive(Debug)]
pub struct MlsCryptoProvider {
    crypto: RustCrypto,
    key_store: CryptoKeystore,
}

impl MlsCryptoProvider {
    pub fn try_new(db_path: impl AsRef<str>, identity_key: impl AsRef<str>) -> CryptoKeystoreResult<Self> {
        let crypto = RustCrypto::default();
        // FIXME: Remove the forced in-memory keystore when WASM persistence stops timing out!
        #[cfg(target_family = "wasm")]
        let key_store = CryptoKeystore::open_in_memory_with_key(db_path, identity_key.as_ref())?;
        #[cfg(not(target_family = "wasm"))]
        let key_store = CryptoKeystore::open_with_key(db_path, identity_key.as_ref())?;
        Ok(Self { crypto, key_store })
    }

    pub fn try_new_in_memory(identity_key: impl AsRef<str>) -> CryptoKeystoreResult<Self> {
        let crypto = RustCrypto::default();
        let key_store = CryptoKeystore::open_in_memory_with_key("", identity_key.as_ref())?;
        Ok(Self { crypto, key_store })
    }

    pub fn destroy_and_reset(self) {
        self.key_store.wipe().unwrap();
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