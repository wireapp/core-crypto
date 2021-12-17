use openmls_rust_crypto::RustCrypto as OpenMlsRustCrypto;
use openmls_traits::OpenMlsCryptoProvider;

#[derive(Debug)]
pub struct MlsCryptoProvider {
    crypto: OpenMlsRustCrypto,
    key_store: keystore::CryptoKeystore,
}

impl OpenMlsCryptoProvider for MlsCryptoProvider {
    type CryptoProvider = OpenMlsRustCrypto;
    type RandProvider = OpenMlsRustCrypto;
    type KeyStoreProvider = keystore::CryptoKeystore;

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
