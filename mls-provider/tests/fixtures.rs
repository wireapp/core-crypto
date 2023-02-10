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
#![allow(non_snake_case, dead_code, unused_macros, unused_imports)]

use getrandom::getrandom;

pub use rstest::*;
pub use rstest_reuse::{self, *};

use mls_crypto_provider::{EntropySeed, MlsCryptoProvider};

const TEST_ENCRYPTION_KEY: &str = "test1234";

pub fn store_name() -> String {
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
pub async fn setup(#[default(false)] in_memory: bool) -> MlsCryptoProvider {
    let store_name = store_name();
    let store = if !in_memory {
        core_crypto_keystore::Connection::open_with_key(store_name, TEST_ENCRYPTION_KEY).await
    } else {
        core_crypto_keystore::Connection::open_in_memory_with_key(store_name, TEST_ENCRYPTION_KEY).await
    }
    .unwrap();

    MlsCryptoProvider::new_with_store(store, None)
}

#[template]
#[rstest]
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
// TODO: Those 3 next ciphersuites aren't supported because of the lack of both p521 (wip) and ed448 (status unknown) crates
// #[case::ed448_aes256_sys_entropy__persistent(
//     setup(false),
//     openmls::prelude::Ciphersuite::MLS_256_DHKEMX448_AES256GCM_SHA512_Ed448,
//     None
// )]
// #[case::ed448_aes256__ext_entropy__persistent(
//     setup(false),
//     openmls::prelude::Ciphersuite::MLS_256_DHKEMX448_AES256GCM_SHA512_Ed448,
//     Some(entropy())
// )]
// #[case::ed448_aes256__sys_entropy__in_memory(
//     setup(true),
//     openmls::prelude::Ciphersuite::MLS_256_DHKEMX448_AES256GCM_SHA512_Ed448,
//     None
// )]
// #[case::ed448_aes256__ext_entropy__in_memory(
//     setup(true),
//     openmls::prelude::Ciphersuite::MLS_256_DHKEMX448_AES256GCM_SHA512_Ed448,
//     Some(entropy())
// )]
// #[case::p521_aes256__sys_entropy__persistent(
//     setup(false),
//     openmls::prelude::Ciphersuite::MLS_256_DHKEMP521_AES256GCM_SHA512_P521,
//     None
// )]
// #[case::p521_aes256__ext_entropy__persistent(
//     setup(false),
//     openmls::prelude::Ciphersuite::MLS_256_DHKEMP521_AES256GCM_SHA512_P521,
//     Some(entropy())
// )]
// #[case::p521_aes256__sys_entropy__in_memory(
//     setup(true),
//     openmls::prelude::Ciphersuite::MLS_256_DHKEMP521_AES256GCM_SHA512_P521,
//     None
// )]
// #[case::p521_aes256__ext_entropy__in_memory(
//     setup(true),
//     openmls::prelude::Ciphersuite::MLS_256_DHKEMP521_AES256GCM_SHA512_P521,
//     Some(entropy())
// )]
// #[case::ed448_chacha20poly1305_sys_entropy__persistent(
//     setup(false),
//     openmls::prelude::Ciphersuite::MLS_256_DHKEMX448_CHACHA20POLY1305_SHA512_Ed448,
//     None
// )]
// #[case::ed448_chacha20poly1305__ext_entropy__persistent(
//     setup(false),
//     openmls::prelude::Ciphersuite::MLS_256_DHKEMX448_CHACHA20POLY1305_SHA512_Ed448,
//     Some(entropy())
// )]
// #[case::ed448_chacha20poly1305__sys_entropy__in_memory(
//     setup(true),
//     openmls::prelude::Ciphersuite::MLS_256_DHKEMX448_CHACHA20POLY1305_SHA512_Ed448,
//     None
// )]
// #[case::ed448_chacha20poly1305__ext_entropy__in_memory(
//     setup(true),
//     openmls::prelude::Ciphersuite::MLS_256_DHKEMX448_CHACHA20POLY1305_SHA512_Ed448,
//     Some(entropy())
// )]
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
pub fn all_storage_types_and_ciphersuites(
    #[case]
    #[future]
    backend: MlsCryptoProvider,
    #[case] ciphersuite: openmls::prelude::Ciphersuite,
    #[case] entropy_seed: Option<EntropySeed>,
) {
}

#[inline(always)]
pub async fn teardown(backend: MlsCryptoProvider) {
    let store = backend.unwrap_keystore();
    store.wipe().await.unwrap();
}
