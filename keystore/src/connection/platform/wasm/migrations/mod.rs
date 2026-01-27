mod db_key_type_to_bytes;
mod delete_credential_by_session_id;
mod migration_connection;
mod pre_v04;
mod v00;
mod v02;
mod v03;
mod v04;
mod v05;
mod v06;
mod v07;
mod v08;
mod v09;
mod v10;

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
const DB_VERSION_10: u32 = db_version_number(10);

/// This must always be the latest version. Increment when adding a new migration.
const TARGET_VERSION: u32 = DB_VERSION_10;

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

/// Open an existing idb database with the given name, and migrate it if needed.
#[cfg(test)]
async fn open_at(name: &str, key: &DatabaseKey, target_version: u32) -> Database {
    let factory = Factory::new().unwrap();
    let existing_db = factory.open(name, None).unwrap().await.unwrap();

    let mut version = existing_db.version().unwrap();
    if version > target_version {
        panic!("version is ahead of target version");
    } else if version == target_version {
        // Migration is not needed, just return existing db
        existing_db
    } else {
        // Migration is needed
        existing_db.close();

        while version < target_version {
            version = do_migration_step(version, name, key).await.unwrap();
        }

        factory.open(name, Some(target_version)).unwrap().await.unwrap()
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
        1 => v04::migrate(name).await,
        DB_VERSION_4 => v05::migrate(name).await,
        DB_VERSION_5 => v06::migrate(name, key).await,
        DB_VERSION_6 => v07::migrate(name, key).await,
        DB_VERSION_7 => v08::migrate(name, key).await,
        DB_VERSION_8 => v09::migrate(name, key).await,
        DB_VERSION_9 => v10::migrate(name, key).await,
        _ => Err(CryptoKeystoreError::MigrationNotSupported(from)),
    }
}

#[cfg(test)]
mod tests {
    use std::sync::LazyLock;

    use idb::builder::{DatabaseBuilder, ObjectStoreBuilder};
    use rand::Rng as _;
    use serde::Serialize as _;
    use wasm_bindgen::JsValue;
    use wasm_bindgen_test::wasm_bindgen_test;

    use super::*;
    use crate::{
        connection::storage::WasmStorageWrapper,
        entities::{ProteusPrekey, StoredCredential},
        traits::{Entity, EntityBase as _, EntityDatabaseMutation as _},
    };

    pub(crate) static TEST_ENCRYPTION_KEY: LazyLock<DatabaseKey> = LazyLock::new(DatabaseKey::generate);

    wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_browser);

    #[wasm_bindgen_test]
    pub async fn can_run_migrations() {
        let name = "test";
        let factory = Factory::new().expect("factory");
        factory.delete(name).expect("delete request").await.expect("wiping db");

        let test_builder = |version| -> DatabaseBuilder {
            v03::get_builder(name)
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
    pub async fn v9_schema_allows_multiple_creds_per_session() {
        let name = "test";
        const LEN_RANGE: std::ops::Range<usize> = 1024..8192;
        let mut rng = rand::thread_rng();

        let builder = v09::get_builder(name);
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

        let builder = v09::get_builder(name);
        let mut conn = crate::Database::migration_connection(builder, &TEST_ENCRYPTION_KEY)
            .await
            .expect("DB_VERSION_9");

        let count = <StoredCredential as Entity>::count(&mut conn)
            .await
            .expect("credential count");

        assert_eq!(count, 2);

        let migrated_db = crate::Database::open(crate::ConnectionType::Persistent(name), &TEST_ENCRYPTION_KEY)
            .await
            .expect("completing migrations");

        migrated_db.close().await.expect("closing connection");
        let factory = Factory::new().expect("factory");
        factory.delete(name).expect("delete request").await.expect("wiping db");
    }

    #[wasm_bindgen_test]
    pub async fn data_is_preserved_through_migrations() {
        const DB_NAME: &str = "test";
        // this entity type is simple, stable from v0 through v10, and we do not expect
        // it to change in the future
        const COLLECTION_NAME: &str = ProteusPrekey::COLLECTION_NAME;

        // clear the factory before beginning
        let factory = Factory::new().unwrap();
        factory.delete(DB_NAME).unwrap().await.unwrap();

        const ENTITY_KEY: u16 = 12345;
        const ENTITY_VALUE: &[u8] = b"here is a test entity, do not mess with it";

        // put some data into a version 4 database
        {
            // version 4 is the earliest version that we natively generate anymore
            let database = open_at(DB_NAME, &TEST_ENCRYPTION_KEY, DB_VERSION_4).await;
            let transaction = database
                .transaction(&[COLLECTION_NAME], idb::TransactionMode::ReadWrite)
                .unwrap();
            let object_store = transaction.object_store(COLLECTION_NAME).unwrap();

            let serializer = serde_wasm_bindgen::Serializer::json_compatible();

            // this is structurally similar to a proper proteus prekey, but notice we're skipping
            // all the encryption/decryption steps as those are irrelevant to the storage feature
            // under test here
            let js_key = ENTITY_KEY.into();
            let js_entity = serde_json::json!({
                "id": ENTITY_KEY,
                "prekey": ENTITY_VALUE,
            })
            .serialize(&serializer)
            .unwrap();
            object_store.put(&js_entity, Some(&js_key)).unwrap();

            transaction.commit().unwrap();
        }

        // get the same data from a current-version database
        {
            let database = open_at(DB_NAME, &TEST_ENCRYPTION_KEY, TARGET_VERSION).await;
            let transaction = database
                .transaction(&[COLLECTION_NAME], idb::TransactionMode::ReadOnly)
                .unwrap();
            let object_store = transaction.object_store(COLLECTION_NAME).unwrap();

            let value = object_store
                .get(JsValue::from(ENTITY_KEY))
                .unwrap()
                .await
                .unwrap()
                .expect("object store contains value at entity key");
            let value = serde_wasm_bindgen::from_value::<serde_json::Value>(value).unwrap();

            let id = value
                .get("id")
                .and_then(serde_json::Value::as_number)
                .and_then(serde_json::Number::as_u64)
                .expect("id is present in value") as u16;
            assert_eq!(id, ENTITY_KEY);

            let prekey = value
                .get("prekey")
                .and_then(serde_json::Value::as_array)
                .expect("prekey is present in value")
                .iter()
                .map(|value| {
                    value
                        .as_number()
                        .expect("value is a number")
                        .as_u64()
                        .expect("value is an integer") as u8
                })
                .collect::<Vec<_>>();
            assert_eq!(prekey, ENTITY_VALUE);
        }
    }
}
