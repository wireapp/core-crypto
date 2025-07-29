use idb::{
    KeyPath,
    builder::{IndexBuilder, ObjectStoreBuilder},
};

use crate::{
    CryptoKeystoreResult,
    entities::{EntityBase as _, Epoch, Group, KeyPackageData, Psk},
};

use super::{DB_VERSION_6, Metabuilder};

/// Open IDB once with the new builder and close it, this will apply the update.
pub(super) async fn migrate(name: &str) -> CryptoKeystoreResult<u32> {
    let migrated_idb = get_builder(name).build().await?;
    let version = migrated_idb.version()?;
    migrated_idb.close();
    Ok(version)
}

/// Just set up the builder for v6.
pub(super) fn get_builder(name: &str) -> Metabuilder {
    super::v5::get_builder(name)
        .version(DB_VERSION_6)
        .add_object_store(
            ObjectStoreBuilder::new(KeyPackageData::COLLECTION_NAME)
                .auto_increment(false)
                .add_index(IndexBuilder::new("id".into(), KeyPath::new_single("id")).unique(true)),
        )
        .add_object_store(
            ObjectStoreBuilder::new(Psk::COLLECTION_NAME)
                .auto_increment(false)
                .add_index(IndexBuilder::new("id".into(), KeyPath::new_single("id")).unique(true)),
        )
        .add_object_store(
            ObjectStoreBuilder::new(Group::COLLECTION_NAME)
                .auto_increment(false)
                .add_index(IndexBuilder::new("id".into(), KeyPath::new_single("id")).unique(true)),
        )
        .add_object_store(
            ObjectStoreBuilder::new(Epoch::COLLECTION_NAME)
                .auto_increment(false)
                .key_path(KeyPath::new_array(["group_id", "epoch_id"]).into())
                .add_index(IndexBuilder::new("by_group_id".into(), KeyPath::new_single("group_id")).unique(false)),
        )
}
