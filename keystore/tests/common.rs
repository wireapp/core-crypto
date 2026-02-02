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
    #[cfg(target_family = "wasm")]
    {
        // we may sometimes want to disable this for manual debugging
        if true {
            use rand::{
                Rng as _,
                distributions::{Alphanumeric, DistString},
            };
            let mut rng = rand::thread_rng();
            let dynamism = Alphanumeric.sample_string(&mut rng, 12);
            format!("corecrypto.{dynamism}.test")
        } else {
            "corecrypto.test".to_owned()
        }
    }

    #[cfg(not(target_family = "wasm"))]
    {
        let tempfile = tempfile::NamedTempFile::with_prefix("corecrypto.test.edb.").unwrap();
        tempfile.path().to_str().unwrap().to_string()
    }
}

#[fixture(name = store_name(), in_memory = false)]
pub async fn setup(name: impl AsRef<str>, in_memory: bool) -> KeystoreTestContext {
    let location = if in_memory {
        ConnectionType::InMemory
    } else {
        ConnectionType::Persistent(name.as_ref())
    };
    #[cfg(target_family = "wasm")]
    console_error_panic_hook::set_once();
    let store = core_crypto_keystore::Database::open(location, &TEST_ENCRYPTION_KEY)
        .await
        .expect("Could not open keystore");
    store.new_transaction().await.expect("Could not create transaction");
    KeystoreTestContext { store: Some(store) }
}

pub(crate) struct KeystoreTestContext {
    store: Option<core_crypto_keystore::Database>,
}

impl KeystoreTestContext {
    pub(crate) fn store(&self) -> &core_crypto_keystore::Database {
        self.store.as_ref().expect("KeystoreTestFixture store is missing")
    }

    pub(crate) fn store_mut(&mut self) -> &mut core_crypto_keystore::Database {
        self.store.as_mut().expect("KeystoreTestFixture store is missing")
    }
}

impl Drop for KeystoreTestContext {
    fn drop(&mut self) {
        if let Some(store) = self.store.take() {
            let rollback_and_wipe = async move {
                store
                    .rollback_transaction()
                    .await
                    .expect("could not rollback transaction");
                store.wipe().await.expect("Could not wipe store");
            };

            #[cfg(not(target_family = "wasm"))]
            futures_lite::future::block_on(rollback_and_wipe);
            #[cfg(target_family = "wasm")]
            wasm_bindgen_futures::spawn_local(rollback_and_wipe);
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
#[cfg_attr(target_family = "wasm", test_attr(wasm_bindgen_test::wasm_bindgen_test))]
pub async fn all_storage_types(#[case] context: KeystoreTestContext) {}
