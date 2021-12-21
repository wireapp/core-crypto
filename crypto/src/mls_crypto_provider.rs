use openmls_rust_crypto::RustCrypto as OpenMlsRustCrypto;
use openmls_traits::OpenMlsCryptoProvider;

#[derive(Debug)]
pub struct MlsCryptoProvider {
    crypto: OpenMlsRustCrypto,
    key_store: core_crypto_keystore::CryptoKeystore,
}

impl MlsCryptoProvider {
    pub fn try_new<S: AsRef<str>>(db_path: S, identity_key: S) -> crate::error::CryptoResult<Self> {
        let crypto = OpenMlsRustCrypto::default();
        let key_store = core_crypto_keystore::CryptoKeystore::open_with_key(db_path, identity_key)?;
        Ok(Self { crypto, key_store })
    }
}

impl OpenMlsCryptoProvider for MlsCryptoProvider {
    type CryptoProvider = OpenMlsRustCrypto;
    type RandProvider = OpenMlsRustCrypto;
    type KeyStoreProvider = core_crypto_keystore::CryptoKeystore;

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
