#![allow(dead_code, unused_macros, unused_imports)]

use std::{
    array,
    sync::{Arc, LazyLock},
};

pub(crate) use core_crypto_keystore::{Database as CryptoKeystore, DatabaseKey};
pub(crate) use rstest::*;
pub(crate) use rstest_reuse::{self, *};

pub(crate) static TEST_ENCRYPTION_KEY: LazyLock<DatabaseKey> = LazyLock::new(DatabaseKey::generate);

#[fixture]
pub fn store_name() -> String {
    #[cfg(target_os = "unknown")]
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

    #[cfg(not(target_os = "unknown"))]
    {
        let tempfile = tempfile::NamedTempFile::with_prefix("corecrypto.test.edb.").unwrap();
        tempfile.path().to_str().unwrap().to_string()
    }
}

#[fixture(name = store_name(), in_memory = false)]
pub async fn setup(name: impl AsRef<str>, in_memory: bool) -> KeystoreTestContext {
    #[cfg(target_os = "unknown")]
    console_error_panic_hook::set_once();

    let database = if in_memory {
        core_crypto_keystore::Database::open_in_memory().expect("Could not open keystore")
    } else {
        core_crypto_keystore::Database::open(name.as_ref(), &TEST_ENCRYPTION_KEY)
            .await
            .expect("Could not open keystore")
    };
    database.new_transaction().await.expect("Could not create transaction");

    KeystoreTestContext { store: Some(database) }
}

pub(crate) struct KeystoreTestContext {
    store: Option<Arc<core_crypto_keystore::Database>>,
}

impl KeystoreTestContext {
    pub(crate) fn store(&self) -> &core_crypto_keystore::Database {
        self.store.as_ref().expect("KeystoreTestFixture store is missing")
    }
}

impl Drop for KeystoreTestContext {
    fn drop(&mut self) {
        if let Some(store) = self.store.take() {
            let rollback_and_wipe = async move {
                let db = Arc::into_inner(store)
                    .expect("when a test is dropped there are no more database refs floating around");
                db.rollback_transaction().await.expect("could not rollback transaction");
                db.wipe().await.expect("Could not wipe store");
            };

            #[cfg(not(target_os = "unknown"))]
            futures_lite::future::block_on(rollback_and_wipe);
            #[cfg(target_os = "unknown")]
            wasm_bindgen_futures::spawn_local(rollback_and_wipe);
        }
    }
}

#[template]
#[rstest]
#[case::persistent(setup(store_name(), false).await)]
#[case::in_memory(setup(store_name(), true).await)]
#[cfg_attr(
    not(target_os = "unknown"),
    test_attr(macro_rules_attribute::apply(smol_macros::test))
)]
#[cfg_attr(target_os = "unknown", test_attr(wasm_bindgen_test::wasm_bindgen_test))]
pub async fn all_storage_types(#[case] context: KeystoreTestContext) {}
