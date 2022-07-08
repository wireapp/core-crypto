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

#![allow(dead_code, unused_macros, unused_imports)]

pub use core_crypto_keystore::Connection as CryptoKeystore;

pub use rstest::*;
pub use rstest_reuse::{self, *};

const TEST_ENCRYPTION_KEY: &str = "test1234";

#[fixture]
pub fn store_name() -> String {
    use rand::Rng as _;
    let mut rng = rand::thread_rng();
    let name: String = (0..6)
        .map(|_| rng.sample(rand::distributions::Alphanumeric) as char)
        .collect();
    cfg_if::cfg_if! {
        if #[cfg(target_family = "wasm")] {
            format!("corecrypto.test.{}.edb", name)
        } else {
            format!("./test.{}.edb", name)
        }
    }
}

#[fixture(name = store_name(), in_memory = false)]
pub async fn setup(name: impl AsRef<str>, in_memory: bool) -> core_crypto_keystore::Connection {
    let store = if !in_memory {
        core_crypto_keystore::Connection::open_with_key(name, TEST_ENCRYPTION_KEY).await
    } else {
        core_crypto_keystore::Connection::open_in_memory_with_key(name, TEST_ENCRYPTION_KEY).await
    }
    .unwrap();
    store
}

#[template]
#[rstest]
#[case::persistent(setup(store_name(), false))]
#[case::in_memory(setup(store_name(), true))]
pub async fn all_storage_types(
    #[case]
    #[future]
    store: core_crypto_keystore::Connection,
) {
}

#[inline(always)]
pub async fn teardown(store: core_crypto_keystore::Connection) {
    store.wipe().await.unwrap();
}
