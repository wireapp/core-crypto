//! This migration gets all mls groups from the store, decrypts them, re-encrypts them, and re-inserts them.
//!
//! This has the effect of upgrading from a `V10PersistedMlsGroup` to a `PersistedMlsGroup`, which differs
//! in that its `parent_id` field is no longer encrypted.

mod v10_persisted_mls_group;

use idb::builder::DatabaseBuilder;
use serde::Serialize as _;

use self::v10_persisted_mls_group::V10PersistedMlsGroup;
use super::DB_VERSION_11;
use crate::{
    CryptoKeystoreResult, Database, DatabaseKey,
    connection::platform::wasm::WasmStorageTransaction,
    entities::PersistedMlsGroup,
    traits::{BorrowPrimaryKey as _, Encrypting as _, Entity as _, EntityBase as _, KeyType as _},
};

/// Open IDB once with the new builder and close it, this will apply the update.
pub(super) async fn migrate(name: &str, key: &DatabaseKey) -> CryptoKeystoreResult<u32> {
    let previous_builder = super::v10::get_builder(name);
    let mut db_during_migration = Database::migration_connection(previous_builder, key).await?;
    let groups = V10PersistedMlsGroup::load_all(&mut db_during_migration)
        .await?
        .into_iter()
        .map(PersistedMlsGroup::from);

    Database::migration_transaction(db_during_migration, async |tx| {
        match tx {
            WasmStorageTransaction::Persistent { tx, cipher } => {
                let serializer = serde_wasm_bindgen::Serializer::json_compatible();
                let store = tx.object_store(PersistedMlsGroup::COLLECTION_NAME)?;
                for group in groups {
                    let key = &js_sys::Uint8Array::from(group.borrow_primary_key().bytes().as_ref()).into();
                    let js_value = group.encrypt(cipher)?.serialize(&serializer)?;
                    store.put(&js_value, Some(key))?.await?;
                }
            }
            WasmStorageTransaction::InMemory { .. } => {
                // in memory transaction is transient and always initialized with the newest database version, so there
                // are no groups to migrate.
            }
        }
        Ok(())
    })
    .await?;

    let migrated_idb = get_builder(name).build().await?;
    let version = migrated_idb.version()?;
    migrated_idb.close();
    Ok(version)
}

/// Set up the builder for v11.
///
/// This has no structural changes; it's a pure data migration.
pub(super) fn get_builder(name: &str) -> DatabaseBuilder {
    super::v10::get_builder(name).version(DB_VERSION_11)
}
