use idb::builder::DatabaseBuilder;

use super::DB_VERSION_5;
use crate::{
    CryptoKeystoreResult,
    connection::idb_migration::legacy::traits::EntityBase as _,
};

/// Open IDB once with the new builder and close it, this will apply the update.
pub(super) async fn migrate(name: &str) -> CryptoKeystoreResult<u32> {
    let migrated_idb = get_builder(name).build().await?;
    let version = migrated_idb.version()?;
    migrated_idb.close();
    Ok(version)
}

/// Just set up the builder for v5.
pub(super) fn get_builder(name: &str) -> DatabaseBuilder {
    super::v04::get_builder(name).version(DB_VERSION_5)
    // this entity no longer exists, so the migration can't do much here,
    // but we leave this remnant as a reminder of why v5 exists at all
    // .remove_object_store(E2eiRefreshToken::COLLECTION_NAME)
}
