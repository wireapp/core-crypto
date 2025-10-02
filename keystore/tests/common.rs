#![allow(dead_code, unused_macros, unused_imports)]

use std::{
    array,
    sync::{Arc, LazyLock},
};

use core_crypto_keystore::connection::{ConnectionType, DatabaseConnection, KeystoreDatabaseConnection};
pub(crate) use core_crypto_keystore::{Database as CryptoKeystore, DatabaseKey};
pub(crate) use rstest::*;
pub(crate) use rstest_reuse::{self, *};

pub(crate) static TEST_ENCRYPTION_KEY: LazyLock<DatabaseKey> = LazyLock::new(DatabaseKey::generate);

#[fixture]
pub fn store_name() -> String {
    use rand::Rng as _;
    let mut rng = rand::thread_rng();
    let name: String = (0usize..12)
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

#[fixture(name = store_name(), in_memory = false)]
pub async fn setup(name: impl AsRef<str>, in_memory: bool) -> KeystoreTestContext {
    let location = if in_memory {
        ConnectionType::InMemory
    } else {
        ConnectionType::Persistent(name.as_ref())
    };
    let store = core_crypto_keystore::Database::open(location, &TEST_ENCRYPTION_KEY)
        .await
        .expect("Could not open keystore");
    store.new_transaction().await.expect("Could not create transaction");
    KeystoreTestContext { store: Some(store) }
}

pub struct KeystoreTestContext {
    store: Option<core_crypto_keystore::Database>,
}

impl KeystoreTestContext {
    pub fn store(&self) -> &core_crypto_keystore::Database {
        self.store.as_ref().expect("KeystoreTestFixture store is missing")
    }

    pub fn store_mut(&mut self) -> &mut core_crypto_keystore::Database {
        self.store.as_mut().expect("KeystoreTestFixture store is missing")
    }
}

impl Drop for KeystoreTestContext {
    fn drop(&mut self) {
        if let Some(store) = self.store.take() {
            let commit_and_wipe = async {
                store.commit_transaction().await.expect("Could not commit transaction");
                store.wipe().await.expect("Could not wipe store");
            };

            #[cfg(not(target_family = "wasm"))]
            futures_lite::future::block_on(commit_and_wipe);
            #[cfg(target_family = "wasm")]
            wasm_bindgen_futures::spawn_local(commit_and_wipe);
        }
    }
}

#[template]
#[rstest]
#[case::persistent(setup(store_name(), false).await)]
#[case::in_memory(setup(store_name(), true).await)]
#[cfg_attr(
    not(target_family = "wasm"),
    test_attr(macro_rules_attribute::apply(smol_macros::test))
)]
#[cfg_attr(target_family = "wasm", test_attr(wasm_bindgen_test))]
pub async fn all_storage_types(#[case] context: KeystoreTestContext) {}
