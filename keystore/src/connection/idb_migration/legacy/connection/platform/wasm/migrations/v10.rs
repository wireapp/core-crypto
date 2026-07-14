//! This migration adds an index on the `parent_id` field to the `mls_groups` table.

use idb::builder::{DatabaseBuilder, IndexBuilder};

use super::DB_VERSION_10;
use crate::{
    CryptoKeystoreResult, DatabaseKey, connection::idb_migration::legacy::traits::EntityBase as _,
    entities::PersistedMlsGroup,
};

/// Open IDB once with the new builder and close it, this will apply the update.
pub(super) async fn migrate(name: &str, _key: &DatabaseKey) -> CryptoKeystoreResult<u32> {
    let migrated_idb = get_builder(name).build().await?;
    let version = migrated_idb.version()?;
    migrated_idb.close();

    Ok(version)
}

/// Set up the builder for v10.
pub(super) fn get_builder(name: &str) -> DatabaseBuilder {
    super::v09::get_builder(name)
        .version(DB_VERSION_10)
        .mutate_object_store(PersistedMlsGroup::COLLECTION_NAME, |builder| {
            builder.add_index(IndexBuilder::new(
                "parent_id".into(),
                idb::KeyPath::Single("parent_id".into()),
            ))
        })
}
