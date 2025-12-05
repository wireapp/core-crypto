use idb::{
    KeyPath,
    builder::{DatabaseBuilder, IndexBuilder, ObjectStoreBuilder},
};

use super::DB_VERSION_2;
use crate::{
    CryptoKeystoreResult,
    entities::{ConsumerData, EntityBase as _},
};

/// Open IDB once with the new builder and close it, this will add the new object store.
pub(super) async fn migrate(name: &str) -> CryptoKeystoreResult<u32> {
    let migrated_idb = get_builder(name).build().await?;
    let version = migrated_idb.version()?;
    migrated_idb.close();
    Ok(version)
}

/// Add a new object store for the ConsumerData struct.
pub(super) fn get_builder(name: &str) -> DatabaseBuilder {
    let previous_builder = super::v0::get_builder(name);
    previous_builder.version(DB_VERSION_2).add_object_store(
        ObjectStoreBuilder::new(ConsumerData::COLLECTION_NAME)
            .auto_increment(false)
            .add_index(IndexBuilder::new("id".into(), KeyPath::new_single("id")).unique(true)),
    )
}
