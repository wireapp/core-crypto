use crate::utils::tmp_db_file;
use core_crypto::proteus::ProteusCentral;
use core_crypto_keystore::Connection;
use futures_lite::future::block_on;
use mls_crypto_provider::CryptoKeystore;
use proteus_wasm::{
    keys,
    keys::{PreKey, PreKeyBundle},
};

pub fn setup_proteus(in_memory: bool) -> (ProteusCentral, CryptoKeystore) {
    let (path, file) = tmp_db_file();
    block_on(async {
        assert!(file.path().exists());
        let keystore = if in_memory {
            Connection::open_in_memory_with_key(&path, "test").await.unwrap()
        } else {
            Connection::open_with_key(&path, "test").await.unwrap()
        };
        (ProteusCentral::try_new(&keystore).await.unwrap(), keystore)
    })
}

pub fn new_prekeys(size: usize) -> Vec<PreKeyBundle> {
    (0..size).map(|_| new_prekey()).collect()
}

pub fn new_prekey() -> PreKeyBundle {
    let kp = keys::IdentityKeyPair::new();
    let prekey = PreKey::new(keys::PreKeyId::new(1));
    PreKeyBundle::new(kp.public_key, &prekey)
}

pub fn session_id() -> String {
    uuid::Uuid::new_v4().hyphenated().to_string()
}
