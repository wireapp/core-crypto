use core_crypto_keystore::{CryptoKeystore, CryptoKeystoreResult};
use openmls_rust_crypto::RustCrypto as OpenMlsRustCrypto;
use openmls_traits::OpenMlsCryptoProvider;

#[derive(Debug)]
pub struct MlsCryptoProvider {
    crypto: OpenMlsRustCrypto,
    key_store: CryptoKeystore,
}

impl MlsCryptoProvider {
    pub fn try_new<S: AsRef<str>, K: AsRef<str>>(
        db_path: S,
        identity_key: K,
    ) -> CryptoKeystoreResult<Self> {
        let crypto = OpenMlsRustCrypto::default();
        let key_store = CryptoKeystore::open_with_key(db_path, identity_key.as_ref())?;
        Ok(Self { crypto, key_store })
    }

    pub fn try_new_in_memory<K: AsRef<str>>(identity_key: K) -> CryptoKeystoreResult<Self> {
        let crypto = OpenMlsRustCrypto::default();
        let key_store = CryptoKeystore::open_in_memory_with_key(identity_key.as_ref())?;
        Ok(Self { crypto, key_store })
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
