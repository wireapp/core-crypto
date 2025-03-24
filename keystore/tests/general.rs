pub use rstest::*;
pub use rstest_reuse::{self, *};

mod common;

#[cfg(test)]
mod tests {
    use crate::common::*;
    #[cfg(target_family = "wasm")]
    use idb::builder::{DatabaseBuilder, ObjectStoreBuilder};
    use wasm_bindgen_test::*;

    wasm_bindgen_test_configure!(run_in_browser);

    #[apply(all_storage_types)]
    #[wasm_bindgen_test]
    pub async fn can_create_and_init_store(_context: KeystoreTestContext) {
        // just runs the setup and teardown, which creates the store and wipes it afterward.
    }

    #[cfg(target_os = "ios")]
    #[cfg_attr(not(target_family = "wasm"), async_std::test)]
    async fn can_preserve_wal_compat_for_ios() {
        let store1 = setup("ios-wal-compat", false).await;
        drop(store1);
        let store2 = setup("ios-wal-compat-2", true).await;
        drop(store2);
        let _store1 = setup("ios-wal-compat", false).await;
    }

    #[cfg(target_family = "wasm")]
    #[wasm_bindgen_test]
    pub async fn can_migrate_new_idb_db_versions() {
        let store_name = store_name();
        let idb = DatabaseBuilder::new(&store_name)
            .version(1)
            .add_object_store(ObjectStoreBuilder::new("regression_check").auto_increment(false))
            .build()
            .await
            .unwrap();

        assert!(idb.store_names().contains(&"regression_check".into()));

        idb.close();

        core_crypto_keystore::Connection::migrate_db_key_type_to_bytes(&store_name, "test1234", &TEST_ENCRYPTION_KEY)
            .await
            .unwrap();

        let store = core_crypto_keystore::Connection::open_with_key(&store_name, &TEST_ENCRYPTION_KEY)
            .await
            .unwrap();

        let mut conn = store.borrow_conn().await.unwrap();
        use core_crypto_keystore::connection::storage::WasmStorageWrapper;
        let WasmStorageWrapper::Persistent(rexie) = conn.storage_mut().wrapper() else {
            panic!("Storage isn't persistent");
        };

        let store_names = rexie.store_names();

        assert!(store_names.contains(&"regression_check".into()));

        assert!(store_names.contains(&"mls_psk_bundles".into()));
        assert!(store_names.contains(&"mls_signature_keypairs".into()));
        assert!(store_names.contains(&"mls_hpke_private_keys".into()));
        assert!(store_names.contains(&"mls_encryption_keypairs".into()));
        assert!(store_names.contains(&"mls_keypackages".into()));
        assert!(store_names.contains(&"mls_credentials".into()));
        assert!(store_names.contains(&"mls_groups".into()));
        assert!(store_names.contains(&"mls_pending_groups".into()));
        assert!(store_names.contains(&"proteus_prekeys".into()));
        assert!(store_names.contains(&"proteus_identities".into()));
        assert!(store_names.contains(&"proteus_sessions".into()));
    }
}
