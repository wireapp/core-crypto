#![allow(non_snake_case, dead_code, unused_macros, unused_imports)]

use getrandom::getrandom;

pub(crate) use rstest::*;
pub(crate) use rstest_reuse::{self, *};

use mls_crypto_provider::{EntropySeed, MlsCryptoProvider};

pub(crate) fn store_name() -> String {
    use rand::Rng as _;
    let mut rng = rand::thread_rng();
    let name: String = (0..12)
        .map(|_| rng.sample(rand::distributions::Alphanumeric) as char)
        .collect();
    cfg_if::cfg_if! {
        if #[cfg(target_family = "wasm")] {
            format!("corecrypto.test.{}.edb", name)
        } else {
            format!("./test.{name}.edb")
        }
    }
}

#[fixture]
pub(crate) async fn setup(#[default(false)] in_memory: bool) -> MlsCryptoProvider {
    let store_name = store_name();
    let key = core_crypto_keystore::DatabaseKey::generate();
    let store = if !in_memory {
        core_crypto_keystore::Database::open(core_crypto_keystore::ConnectionType::Persistent(&store_name), &key).await
    } else {
        core_crypto_keystore::Database::open(core_crypto_keystore::ConnectionType::InMemory, &key).await
    }
    .unwrap();

    MlsCryptoProvider::new(store)
}

#[template]
#[rstest]
#[cfg_attr(
    not(target_family = "wasm"),
    test_attr(macro_rules_attribute::apply(smol_macros::test))
)]
#[cfg_attr(target_family = "wasm", test_attr(wasm_bindgen_test))]
async fn use_provider(
    #[from(setup)]
    #[with(true)]
    #[future]
    backend: MlsCryptoProvider,
) {
}

#[fixture]
pub fn entropy() -> EntropySeed {
    let mut seed: EntropySeed = Default::default();
    getrandom(&mut seed).unwrap();
    seed
}

#[template]
#[rstest]
#[case::ed25519_aes128__sys_entropy__persistent(
    setup(false),
    openmls::prelude::Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519,
    None
)]
#[case::ed25519_aes128__ext_entropy__persistent(
    setup(false),
    openmls::prelude::Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519,
    Some(entropy())
)]
#[case::ed25519_aes128__sys_entropy__in_memory(
    setup(true),
    openmls::prelude::Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519,
    None
)]
#[case::ed25519_aes128__ext_entropy__in_memory(
    setup(true),
    openmls::prelude::Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519,
    Some(entropy())
)]
#[case::p256_aes128__sys_entropy__persistent(
    setup(false),
    openmls::prelude::Ciphersuite::MLS_128_DHKEMP256_AES128GCM_SHA256_P256,
    None
)]
#[case::p256_aes128__ext_entropy__persistent(
    setup(false),
    openmls::prelude::Ciphersuite::MLS_128_DHKEMP256_AES128GCM_SHA256_P256,
    Some(entropy())
)]
#[case::p256_aes128__sys_entropy__in_memory(
    setup(true),
    openmls::prelude::Ciphersuite::MLS_128_DHKEMP256_AES128GCM_SHA256_P256,
    None
)]
#[case::p256_aes128__ext_entropy__in_memory(
    setup(true),
    openmls::prelude::Ciphersuite::MLS_128_DHKEMP256_AES128GCM_SHA256_P256,
    Some(entropy())
)]
#[case::ed25519_chacha20poly1305__sys_entropy__persistent(
    setup(false),
    openmls::prelude::Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519,
    None
)]
#[case::ed25519_chacha20poly1305__ext_entropy__persistent(
    setup(false),
    openmls::prelude::Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519,
    Some(entropy())
)]
#[case::ed25519_chacha20poly1305__sys_entropy__in_memory(
    setup(true),
    openmls::prelude::Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519,
    None
)]
#[case::ed25519_chacha20poly1305__ext_entropy__in_memory(
    setup(true),
    openmls::prelude::Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519,
    Some(entropy())
)]
#[case::p521_aes256__sys_entropy__persistent(
    setup(false),
    openmls::prelude::Ciphersuite::MLS_256_DHKEMP521_AES256GCM_SHA512_P521,
    None
)]
#[case::p521_aes256__ext_entropy__persistent(
    setup(false),
    openmls::prelude::Ciphersuite::MLS_256_DHKEMP521_AES256GCM_SHA512_P521,
    Some(entropy())
)]
#[case::p521_aes256__sys_entropy__in_memory(
    setup(true),
    openmls::prelude::Ciphersuite::MLS_256_DHKEMP521_AES256GCM_SHA512_P521,
    None
)]
#[case::p521_aes256__ext_entropy__in_memory(
    setup(true),
    openmls::prelude::Ciphersuite::MLS_256_DHKEMP521_AES256GCM_SHA512_P521,
    Some(entropy())
)]
#[case::p384_aes256__sys_entropy__persistent(
    setup(false),
    openmls::prelude::Ciphersuite::MLS_256_DHKEMP384_AES256GCM_SHA384_P384,
    None
)]
#[case::p384_aes256__ext_entropy__persistent(
    setup(false),
    openmls::prelude::Ciphersuite::MLS_256_DHKEMP384_AES256GCM_SHA384_P384,
    Some(entropy())
)]
#[case::p384_aes256__sys_entropy__in_memory(
    setup(true),
    openmls::prelude::Ciphersuite::MLS_256_DHKEMP384_AES256GCM_SHA384_P384,
    None
)]
#[case::p384_aes256__ext_entropy__in_memory(
    setup(true),
    openmls::prelude::Ciphersuite::MLS_256_DHKEMP384_AES256GCM_SHA384_P384,
    Some(entropy())
)]
#[cfg_attr(
    not(target_family = "wasm"),
    test_attr(macro_rules_attribute::apply(smol_macros::test))
)]
#[cfg_attr(target_family = "wasm", test_attr(wasm_bindgen_test))]
pub fn all_storage_types_and_ciphersuites(
    #[case]
    #[future]
    backend: MlsCryptoProvider,
    #[case] ciphersuite: openmls::prelude::Ciphersuite,
    #[case] entropy_seed: Option<EntropySeed>,
) {
}

#[inline(always)]
pub(crate) async fn teardown(backend: MlsCryptoProvider) {
    let store = backend.unwrap_keystore();
    store.wipe().await.unwrap();
}
