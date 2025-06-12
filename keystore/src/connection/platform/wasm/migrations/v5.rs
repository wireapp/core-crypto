use super::{DB_VERSION_5, Metabuilder};
use crate::{
    CryptoKeystoreResult,
    entities::{E2eiRefreshToken, EntityBase as _},
};

/// Open IDB once with the new builder and close it, this will apply the update.
pub(super) async fn migrate(name: &str) -> CryptoKeystoreResult<u32> {
    let migrated_idb = get_builder(name).build().await?;
    let version = migrated_idb.version()?;
    migrated_idb.close();
    Ok(version)
}

/// Just set up the builder for v5.
pub(super) fn get_builder(name: &str) -> Metabuilder {
    super::v4::get_builder(name)
        .version(DB_VERSION_5)
        .remove_object_store(E2eiRefreshToken::COLLECTION_NAME)
}
