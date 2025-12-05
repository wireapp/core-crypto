use idb::builder::DatabaseBuilder;

use super::DB_VERSION_4;
use crate::CryptoKeystoreResult;

/// Open IDB once with the new builder and close it, this will add the new object store.
pub(super) async fn migrate(name: &str) -> CryptoKeystoreResult<u32> {
    let migrated_idb = get_builder(name).build().await?;
    let version = migrated_idb.version()?;
    migrated_idb.close();
    Ok(version)
}

/// Just initialize object stores.
pub(super) fn get_builder(name: &str) -> DatabaseBuilder {
    super::v3::get_builder(name).version(DB_VERSION_4)
}
