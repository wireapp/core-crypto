use crate::utils::setup_mls;

use core_crypto::CoreCrypto;
use proteus_wasm::{
    keys,
    keys::{PreKey, PreKeyBundle},
};

pub(crate) async fn setup_proteus(in_memory: bool) -> CoreCrypto {
    let (core_crypto, _) = setup_mls(Default::default(), Default::default(), in_memory).await;
    core_crypto.proteus_init().await.unwrap();
    core_crypto
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
