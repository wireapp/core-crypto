use crate::keystore::TestKeyStore;
use openmls::prelude::OpenMlsCryptoProvider;
use openmls_rust_crypto::RustCrypto;

use std::path::Path;

pub struct TestBackend {
    crypto: RustCrypto,
    key_store: TestKeyStore,
}

impl TestBackend {
    pub fn new<P: AsRef<Path>>(path: P) -> std::io::Result<Self> {
        let crypto = RustCrypto::default();
        let key_store = TestKeyStore::create(path)?;
        Ok(TestBackend { crypto, key_store })
    }
}

impl OpenMlsCryptoProvider for TestBackend {
    type CryptoProvider = RustCrypto;
    type RandProvider = RustCrypto;
    type KeyStoreProvider = TestKeyStore;

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
