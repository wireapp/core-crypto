mod db_key_type_to_bytes;
pub mod keystore_v_1_0_0;
mod metabuilder;
mod pre_v4;
mod v0;
mod v1;
mod v2;
mod v3;
mod v4;
mod v5;

pub(super) use db_key_type_to_bytes::migrate_db_key_type_to_bytes;
use metabuilder::Metabuilder;
/// TODO: this is here only because it's needed for the cryptobox migration test.
///       Once we drop cryptobox migration and the related test, drop this too.
pub use pre_v4::open_and_migrate as open_and_migrate_pre_v4;

use crate::{CryptoKeystoreError, CryptoKeystoreResult, connection::DatabaseKey};
use idb::{Database, Factory};

const fn db_version_number(counter: u32) -> u32 {
    // When the DB version was tied to core crypto, the version counter was the sum of 10_000_000
    // for a major version, 1_000 for a patch version. I.e., the number for v1.0.2 was:
    const VERSION_1_0_2: u32 = 10_000_000 + 2_000;
    // From post v1.0.2, we will just increment whenever we need a DB migration.
    VERSION_1_0_2 + counter
}

const DB_VERSION_0: u32 = db_version_number(0);
const DB_VERSION_1: u32 = db_version_number(1);
const DB_VERSION_2: u32 = db_version_number(2);
const DB_VERSION_3: u32 = db_version_number(3);
const DB_VERSION_4: u32 = db_version_number(4);
const DB_VERSION_5: u32 = db_version_number(5);

/// Open an existing idb database with the given name, and migrate it if needed.
pub(crate) async fn open_and_migrate(name: &str, key: &DatabaseKey) -> CryptoKeystoreResult<Database> {
    /// Increment when adding a new migration.
    const TARGET_VERSION: u32 = DB_VERSION_5;
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
async fn do_migration_step(from: u32, name: &str, _key: &DatabaseKey) -> CryptoKeystoreResult<u32> {
    match from {
        // idb returns version 1 for freshly opened databases so here we just
        // need to initialize object stores.
        1 => v4::migrate(name).await,
        DB_VERSION_4 => v5::migrate(name).await,
        _ => Err(CryptoKeystoreError::MigrationNotSupported(from)),
    }
}
