mod db_key_type_to_bytes;
mod delete_credential_by_session_id;
mod migration_connection;
mod pre_v4;
mod v0;
mod v2;
mod v3;
mod v4;
mod v5;
mod v6;
mod v7;
mod v8;
mod v9;

pub(super) use db_key_type_to_bytes::migrate_db_key_type_to_bytes;
pub(super) use delete_credential_by_session_id::delete_credential_by_session_id;
use idb::{Database, Factory};

use crate::{CryptoKeystoreError, CryptoKeystoreResult, connection::DatabaseKey};

const fn db_version_number(counter: u32) -> u32 {
    // When the DB version was tied to core crypto, the version counter was the sum of 10_000_000
    // for a major version, 1_000 for a patch version. I.e., the number for v1.0.2 was:
    const VERSION_1_0_2: u32 = 10_000_000 + 2_000;
    // From post v1.0.2, we will just increment whenever we need a DB migration.
    VERSION_1_0_2 + counter
}

// Note that we no longer support migration to DB_VERSION_1.
const DB_VERSION_0: u32 = db_version_number(0);
const DB_VERSION_1: u32 = db_version_number(1);
const DB_VERSION_2: u32 = db_version_number(2);
const DB_VERSION_3: u32 = db_version_number(3);
const DB_VERSION_4: u32 = db_version_number(4);
const DB_VERSION_5: u32 = db_version_number(5);
const DB_VERSION_6: u32 = db_version_number(6);
const DB_VERSION_7: u32 = db_version_number(7);
const DB_VERSION_8: u32 = db_version_number(8);
const DB_VERSION_9: u32 = db_version_number(9);

/// This must always be the latest version. Increment when adding a new migration.
const TARGET_VERSION: u32 = DB_VERSION_9;

/// Open an existing idb database with the given name, and migrate it if needed.
pub(crate) async fn open_and_migrate(name: &str, key: &DatabaseKey) -> CryptoKeystoreResult<Database> {
    let factory = Factory::new()?;

    let open_existing = factory.open(name, None)?;
    let existing_db = open_existing.await?;
    let mut version = existing_db.version()?;
    if version == TARGET_VERSION {
        // Migration is not needed, just return existing db
        Ok(existing_db)
    } else {
        // Migration is needed
        existing_db.close();

        while version < TARGET_VERSION {
            version = do_migration_step(version, name, key).await?;
        }

        let open_request = factory.open(name, Some(TARGET_VERSION))?;
        open_request.await.map_err(Into::into)
    }
}

/// The `from` argument represents the version the migration is performed from the function will
/// return the version number of the DB resulting from the migration.
///
/// To add a new migration, add a new match arm below the latest one.
/// It must match on the version it migrates from, and call a function that performs the migration
/// workload, which returns the version it migrates to, which is the same value as TARGET_VERSION in
/// the function above at the time the migration is added.
///
/// However, do not use the constant but hardcode the value into the function.
/// This way it will keep working once a new migration is added after it.
async fn do_migration_step(from: u32, name: &str, key: &DatabaseKey) -> CryptoKeystoreResult<u32> {
    match from {
        // idb returns version 1 for freshly opened databases so here we just
        // need to initialize object stores.
        1 => v4::migrate(name).await,
        DB_VERSION_4 => v5::migrate(name).await,
        DB_VERSION_5 => v6::migrate(name, key).await,
        DB_VERSION_6 => v7::migrate(name, key).await,
        DB_VERSION_7 => v8::migrate(name, key).await,
        DB_VERSION_8 => v9::migrate(name, key).await,
        _ => Err(CryptoKeystoreError::MigrationNotSupported(from)),
    }
}
#[cfg(test)]
mod tests {
    use std::sync::LazyLock;

    use idb::builder::{DatabaseBuilder, ObjectStoreBuilder};
    use rand::Rng as _;
    use serde::Serialize as _;
    use wasm_bindgen_test::wasm_bindgen_test;

    use super::*;
    use crate::{
        connection::{platform::wasm::WasmStorageTransaction, storage::WasmStorageWrapper},
        entities::{Entity, EntityBase, EntityTransactionExt, StoredCredential},
    };

    pub(crate) static TEST_ENCRYPTION_KEY: LazyLock<DatabaseKey> = LazyLock::new(DatabaseKey::generate);

    wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_browser);

    #[wasm_bindgen_test]
    pub async fn can_run_migrations() {
        let name = "test";

        let test_builder = |version| -> DatabaseBuilder {
            v3::get_builder(name)
                .add_object_store(ObjectStoreBuilder::new("regression_check").auto_increment(false))
                .version(version)
        };

        let idb = test_builder(DB_VERSION_3).build().await.expect("DB VERSION 3");

        assert!(idb.store_names().contains(&"regression_check".into()));
        idb.close();

        crate::Database::migrate_db_key_type_to_bytes(name, "test1234", &TEST_ENCRYPTION_KEY)
            .await
            .unwrap();

        let mut conn = crate::Database::migration_connection(test_builder(DB_VERSION_4), &TEST_ENCRYPTION_KEY)
            .await
            .expect("DB_VERSION_4");

        let WasmStorageWrapper::Persistent(db) = conn.storage_mut().wrapper() else {
            panic!("Storage isn't persistent");
        };

        let store_names = db.store_names();

        assert!(store_names.contains(&"regression_check".into()));

        assert!(store_names.contains(&"mls_psk_bundles".into()));
        assert!(store_names.contains(&"mls_hpke_private_keys".into()));
        assert!(store_names.contains(&"mls_encryption_keypairs".into()));
        assert!(store_names.contains(&"mls_keypackages".into()));
        assert!(store_names.contains(&"mls_credentials".into()));
        assert!(store_names.contains(&"mls_groups".into()));
        assert!(store_names.contains(&"mls_pending_groups".into()));
        assert!(store_names.contains(&"proteus_prekeys".into()));
        assert!(store_names.contains(&"proteus_identities".into()));
        assert!(store_names.contains(&"proteus_sessions".into()));
        conn.close().await.expect("closing connection");

        let migrated_db = crate::Database::open(crate::ConnectionType::Persistent(name), &TEST_ENCRYPTION_KEY)
            .await
            .expect("completing migrations");

        migrated_db.close().await.expect("closing connection");
        let factory = Factory::new().expect("factory");
        factory.delete(name).expect("delete request").await.expect("wiping db");
    }

    #[wasm_bindgen_test]
    pub async fn v5_schema_allows_1_cred_per_session() {
        let name = "test";

        let test_builder = |version| -> DatabaseBuilder {
            v3::get_builder(name)
                .add_object_store(ObjectStoreBuilder::new("regression_check").auto_increment(false))
                .version(version)
        };

        let idb = test_builder(DB_VERSION_3).build().await.expect("DB VERSION 3");
        idb.close();

        crate::Database::migrate_db_key_type_to_bytes(name, "test1234", &TEST_ENCRYPTION_KEY)
            .await
            .unwrap();

        let builder = v5::get_builder(name);
        let conn = crate::Database::migration_connection(builder, &TEST_ENCRYPTION_KEY)
            .await
            .expect("DB_VERSION_6");

        const LEN_RANGE: std::ops::Range<usize> = 1024..8192;

        let mut rng = rand::thread_rng();

        crate::Database::migration_transaction(conn, async |tx| {
            use openmls::prelude::Ciphersuite;

            use crate::entities::StoredCredential;

            let mut random_vec = || {
                let len = rng.gen_range(LEN_RANGE);
                let v: Vec<u8> = (0..len).map(|_| rng.r#gen()).collect();
                v
            };

            let cred_a = StoredCredential {
                session_id: random_vec(),
                credential: random_vec(),
                created_at: 2025,
                ciphersuite: Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519 as u16,
                public_key: random_vec(),
                private_key: random_vec(),
            };

            // Try creating a duplicate of this credential
            let mut cred_b = cred_a.clone();
            cred_b.credential = random_vec();
            cred_b.ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519 as u16;

            let credentials = [cred_a, cred_b];
            match tx {
                WasmStorageTransaction::Persistent { tx, cipher } => {
                    let serializer = serde_wasm_bindgen::Serializer::json_compatible();
                    let store = tx.object_store(StoredCredential::COLLECTION_NAME)?;
                    for mut credential in credentials {
                        // Save credentials with session id as key
                        let key = &js_sys::Uint8Array::from(credential.session_id.as_slice()).into();
                        credential.encrypt(cipher)?;
                        let js_value = credential.serialize(&serializer)?;
                        store.put(&js_value, Some(key))?.await?;
                    }
                }
                WasmStorageTransaction::InMemory { .. } => {}
            }

            Ok(())
        })
        .await
        .expect("inserting test data");

        let builder = v6::get_builder(name);
        let mut conn = crate::Database::migration_connection(builder, &TEST_ENCRYPTION_KEY)
            .await
            .expect("DB_VERSION_6");

        let count = StoredCredential::count(&mut conn).await.expect("credential count");

        assert_eq!(
            count, 1,
            "saving two different credentials by the same session id will result in a single credential"
        );

        let migrated_db = crate::Database::open(crate::ConnectionType::Persistent(name), &TEST_ENCRYPTION_KEY)
            .await
            .expect("completing migrations");
        migrated_db.close().await.expect("closing connection");
        let factory = Factory::new().expect("factory");
        factory.delete(name).expect("delete request").await.expect("wiping db");
    }

    #[wasm_bindgen_test]
    pub async fn v9_schema_allows_multiple_creds_per_session() {
        let name = "test";
        const LEN_RANGE: std::ops::Range<usize> = 1024..8192;
        let mut rng = rand::thread_rng();

        let builder = v9::get_builder(name);
        let conn = crate::Database::migration_connection(builder, &TEST_ENCRYPTION_KEY)
            .await
            .expect("DB_VERSION_9");

        crate::Database::migration_transaction(conn, async |tx| {
            use openmls::prelude::Ciphersuite;

            use crate::entities::StoredCredential;

            let mut random_vec = || {
                let len = rng.gen_range(LEN_RANGE);
                let v: Vec<u8> = (0..len).map(|_| rng.r#gen()).collect();
                v
            };

            let cred_a = StoredCredential {
                session_id: random_vec(),
                credential: random_vec(),
                created_at: 2025,
                ciphersuite: Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519 as u16,
                public_key: random_vec(),
                private_key: random_vec(),
            };

            // Insert a second credential
            let mut cred_b = cred_a.clone();
            cred_b.public_key = random_vec();

            let credentials = [cred_a, cred_b];
            for credential in credentials {
                credential.save(tx).await?;
            }

            Ok(())
        })
        .await
        .expect("inserting test data");

        let builder = v9::get_builder(name);
        let mut conn = crate::Database::migration_connection(builder, &TEST_ENCRYPTION_KEY)
            .await
            .expect("DB_VERSION_9");

        let count = StoredCredential::count(&mut conn).await.expect("credential count");

        assert_eq!(count, 2);

        let migrated_db = crate::Database::open(crate::ConnectionType::Persistent(name), &TEST_ENCRYPTION_KEY)
            .await
            .expect("completing migrations");

        migrated_db.close().await.expect("closing connection");
        let factory = Factory::new().expect("factory");
        factory.delete(name).expect("delete request").await.expect("wiping db");
    }
}
