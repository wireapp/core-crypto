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

use core_crypto_keystore::{CryptoKeystore, CryptoKeystoreResult};
use openmls_rust_crypto::RustCrypto as OpenMlsRustCrypto;
use openmls_traits::OpenMlsCryptoProvider;

#[derive(Debug)]
pub struct MlsCryptoProvider {
    crypto: OpenMlsRustCrypto,
    key_store: CryptoKeystore,
}

impl MlsCryptoProvider {
    pub fn try_new<S: AsRef<str>, K: AsRef<str>>(db_path: S, identity_key: K) -> CryptoKeystoreResult<Self> {
        let crypto = OpenMlsRustCrypto::default();
        let key_store = CryptoKeystore::open_with_key(db_path, identity_key.as_ref())?;
        Ok(Self { crypto, key_store })
    }

    pub fn try_new_in_memory<K: AsRef<str>>(identity_key: K) -> CryptoKeystoreResult<Self> {
        let crypto = OpenMlsRustCrypto::default();
        let key_store = CryptoKeystore::open_in_memory_with_key(identity_key.as_ref())?;
        Ok(Self { crypto, key_store })
    }

    pub fn destroy_and_reset(self) {
        self.key_store.delete_database_but_please_be_sure().unwrap();
    }
}

impl OpenMlsCryptoProvider for MlsCryptoProvider {
    type CryptoProvider = OpenMlsRustCrypto;
    type RandProvider = OpenMlsRustCrypto;
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
