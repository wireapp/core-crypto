//! This module runs migrations for databases with version < 4.
//!
//! Migrations here must only be used by `migrate_db_key_type_to_bytes`.

use super::*;

/// Open an existing idb database with the given name and key, and migrate it if needed.
/// The key is only being used for the 0 -> 1 migration, which needs the key as a string.
///
/// TODO: this is pub only because it's needed for the cryptobox migration test.
///       Once we drop cryptobox migration and the related test, make this pub(super) again.
pub async fn open_and_migrate(name: &str, key: &str) -> CryptoKeystoreResult<Database> {
    /// Do not update this target version. The last version that this function
    /// should upgrade to is DB_VERSION_3, because to update to DB_VERSION_4,
    /// clients need to call migrate_db_key_type_to_bytes.
    const TARGET_VERSION: u32 = DB_VERSION_3;
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

// See comments on super::do_migration_step.
async fn do_migration_step(from: u32, name: &str, key: &str) -> CryptoKeystoreResult<u32> {
    match from {
        // The version that results from the latest migration must match TARGET_VERSION
        //      to ensure convergence of the while loop this is called from.
        0..=DB_VERSION_0 => super::v1::migrate(name, key).await,
        DB_VERSION_1 => super::v2::migrate(name).await,
        DB_VERSION_2 => super::v3::migrate(name).await,
        _ => Err(CryptoKeystoreError::MigrationNotSupported(from)),
    }
}
