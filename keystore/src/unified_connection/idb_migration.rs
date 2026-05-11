//! Migration of data from the legacy IndexedDB-based storage to the unified rusqlite connection.
//!
//! On WASM, this is called during [`super::Database::open_internal`] via [`super::os_unknown::open`]
//! to detect and migrate legacy data before the new connection is initialised.

use idb::Factory;
use rusqlite::{Connection, OptionalExtension as _};

#[cfg(feature = "proteus-keystore")]
use crate::entities::{ProteusIdentity, ProteusPrekey, ProteusSession};
use crate::{
    CryptoKeystoreResult, DatabaseKey,
    connection::{DatabaseConnection as _, KeystoreDatabaseConnection},
    entities::{
        ConsumerData, E2eiAcmeCA, E2eiCrl, E2eiIntermediateCert, MlsPendingMessage, PersistedMlsGroup,
        PersistedMlsPendingGroup, StoredBufferedCommit, StoredCredential, StoredE2eiEnrollment,
        StoredEncryptionKeyPair, StoredEpochEncryptionKeypair, StoredHpkePrivateKey, StoredKeypackage, StoredPskBundle,
    },
    traits::{Entity as _, UnifiedEntityDatabaseMutation as _},
    unified_connection::migrations::MigrationTarget,
};

/// Returns `true` if a legacy IndexedDB database with the given name exists and contains data.
///
/// A freshly-created (empty) IDB database always has version 1; any version greater than 1
/// indicates that the legacy migration sequence has been applied and there may be data present.
pub async fn legacy_idb_exists(name: &str) -> bool {
    let Ok(factory) = Factory::new() else {
        return false;
    };
    let Ok(req) = factory.open(name, None) else {
        return false;
    };
    let Ok(db) = req.await else {
        return false;
    };
    let version = db.version().unwrap_or(0);
    db.close();
    version > 1
}

/// Delete the legacy IndexedDB database with the given name.
///
/// This is exposed publicly so that callers can retry deletion independently if it fails during
/// [`maybe_migrate`] (e.g. after a crash between a successful data copy and a failed cleanup).
pub async fn delete_legacy_idb(name: &str) -> CryptoKeystoreResult<()> {
    let factory = Factory::new()?;
    factory.delete(name)?.await?;
    Ok(())
}

/// If a legacy IDB database exists at `name`, migrate all its data into the new connection
/// stored in the VFS identified by `vfs_name`, then delete the legacy IDB.
///
/// Precondition: `new_conn` has not yet had migrations applied, but has been decrypted.
///
/// Postconditions:
/// - all data from the legacy IDB database is moved to `new_conn`
/// - the legacy IDB database is deleted
/// - `new_conn` is _not_ fully migrated and requires a further migration to the latest version
///
/// This is a no-op when:
/// - the unified rusqlite database already exists (already migrated or native platform), or
/// - no legacy IDB database exists at `name` (fresh install).
pub(super) async fn maybe_migrate(
    name: &str,
    database_key: &DatabaseKey,
    new_conn: &mut Connection,
) -> CryptoKeystoreResult<()> {
    /// This SQL database version corresponds to the final IDB version,
    /// so is what we need to perform the migration from IDB
    const SQL_DATABASE_VERSION_AS_OF_FINAL_IDB_VERSION: u16 = 22;

    if !legacy_idb_exists(name).await {
        return Ok(());
    }
    let version = new_conn
        .query_row("PRAGMA user_version;", [], |row| row.get::<_, i32>(0))
        .optional()?;
    if version.is_some_and(|version| version != 0) {
        // a migration has been applied, so the rusqlite database exists, so we're done
        return Ok(());
    }

    // open the legacy IDB, running all IDB migrations (v0 → v11) in the process.
    let mut legacy_conn = KeystoreDatabaseConnection::open(name, database_key).await?;

    // migrate the new connection to the version corresponding to the final IDB migration version
    super::migrations::run_migrations(
        new_conn,
        MigrationTarget::Version(SQL_DATABASE_VERSION_AS_OF_FINAL_IDB_VERSION),
    )?;

    macro_rules! migrate_entities {
        ($( $(#[$attribute:meta])* $entity:ty ),* $(,)?) => {
            paste::paste! {
                // load all entities into memory -- probably fine, but we could consider interweaving
                // a bit and dropping each entity's list after it's saved to the transaction
                // if memory usage proves to be an issue
                $(
                    $(#[$attribute])*
                    let [<$entity:lower>] = $entity::load_all(&mut legacy_conn).await?;
                )*
                drop(legacy_conn);

                // write all entities into the rusqlite database
                let tx = new_conn.transaction()?;
                $(
                    $(#[$attribute])*
                    for row in [<$entity:lower>] {
                        // note: no pre-save; preserve creation times etc
                        row.save(&tx)?;
                    }
                )*
                tx.commit()?;
            }
        };
    }

    // E2eiRefreshToken is intentionally not migrated: it was dropped in SQL migration V15.
    migrate_entities!(
        ConsumerData,
        E2eiAcmeCA,
        E2eiCrl,
        E2eiIntermediateCert,
        MlsPendingMessage,
        PersistedMlsGroup,
        PersistedMlsPendingGroup,
        StoredBufferedCommit,
        StoredCredential,
        StoredE2eiEnrollment,
        StoredEncryptionKeyPair,
        StoredEpochEncryptionKeypair,
        StoredHpkePrivateKey,
        StoredKeypackage,
        StoredPskBundle,
        #[cfg(feature = "proteus-keystore")]
        ProteusIdentity,
        #[cfg(feature = "proteus-keystore")]
        ProteusPrekey,
        #[cfg(feature = "proteus-keystore")]
        ProteusSession,
    );

    // clients can recover independently from this; the migrations all succeeded, so no need to
    // propagate an error
    if let Err(err) = delete_legacy_idb(name).await {
        log::warn!(err:err; "failed to delete legacy IDB database during migration to rusqlite");
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::sync::LazyLock;

    use wasm_bindgen_test::wasm_bindgen_test;

    use super::*;
    use crate::{
        connection::{Database as OldDatabase, platform::wasm::migrations::DB_VERSION_4},
        entities::ProteusPrekey,
        traits::{CryptoTransaction as _, UnifiedEntity},
        unified_connection::Database as NewDatabase,
    };
    pub(crate) static TEST_ENCRYPTION_KEY: LazyLock<DatabaseKey> = LazyLock::new(DatabaseKey::generate);

    wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_browser);

    #[wasm_bindgen_test]
    pub(crate) async fn data_is_preserved_through_migrations() {
        const DB_NAME: &str = "test";

        // clear the factory before beginning
        let factory = Factory::new().unwrap();
        factory.delete(DB_NAME).unwrap().await.unwrap();

        const ENTITY_KEY: u16 = 12345;
        const ENTITY_VALUE: &[u8] = b"here is a test entity, do not mess with it";

        // put some data into a version 4 database
        {
            // version 4 is the earliest version that we natively generate anymore
            let database = OldDatabase::open_at_schema_version(DB_NAME, &TEST_ENCRYPTION_KEY, Some(DB_VERSION_4))
                .await
                .unwrap();

            // this entity type is simple, stable from v0 through v10, and we do not expect
            // it to change in the future
            let prekey = ProteusPrekey::from_raw(ENTITY_KEY, ENTITY_VALUE.into());

            database.new_transaction().await.unwrap();
            database.save(prekey).await.unwrap();
            database.commit_transaction().await.unwrap();
        }

        // now migrate to Rusqlite, open the DB, and retrieve the data
        {
            let database = NewDatabase::open(DB_NAME, &TEST_ENCRYPTION_KEY).await.unwrap();
            let value = <ProteusPrekey as UnifiedEntity>::get(&database.conn, &ENTITY_KEY)
                .expect("no db failure")
                .expect("entity present in the db");

            assert_eq!(value.id, ENTITY_KEY);
            assert_eq!(value.prekey, ENTITY_VALUE);
        }

        // cleanup
        factory.delete(DB_NAME).unwrap().await.unwrap();
    }
}
