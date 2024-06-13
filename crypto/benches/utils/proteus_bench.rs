use crate::utils::tmp_db_file;
use core_crypto::proteus::ProteusCentral;
use core_crypto_keystore::Connection;

use mls_crypto_provider::CryptoKeystore;
use proteus_wasm::{
    keys,
    keys::{PreKey, PreKeyBundle},
};

pub(crate) async fn setup_proteus(in_memory: bool) -> (ProteusCentral, CryptoKeystore) {
    let (path, file) = tmp_db_file();
    assert!(file.path().exists());
    let keystore = if in_memory {
        Connection::open_in_memory_with_key(&path, "test").await.unwrap()
    } else {
        Connection::open_with_key(&path, "test").await.unwrap()
    };
    (ProteusCentral::try_new(&keystore).await.unwrap(), keystore)
}

pub(crate) fn new_prekeys(size: usize) -> Vec<PreKeyBundle> {
    (0..size).map(|_| new_prekey()).collect()
}

pub(crate) fn new_prekey() -> PreKeyBundle {
    let kp = keys::IdentityKeyPair::new();
    let prekey = PreKey::new(keys::PreKeyId::new(1));
    PreKeyBundle::new(kp.public_key, &prekey)
}

pub(crate) fn session_id() -> String {
    uuid::Uuid::new_v4().hyphenated().to_string()
}
