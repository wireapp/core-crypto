//! This migration copies readable credentials into a new store, then swaps it in for the old one.

use idb::builder::DatabaseBuilder;
use serde::Serialize as _;

use super::DB_VERSION_9;
use crate::{
    CryptoKeystoreResult, DatabaseKey,
    connection::idb_migration::legacy::{
        connection::{Database, platform::wasm::WasmStorageTransaction},
        traits::{Encrypting as _, EntityBase as _},
    },
    migrations::historical::StoredCredentialV36,
};

/// Open IDB once with the new builder and close it, this will apply the update.
pub(super) async fn migrate(name: &str, key: &DatabaseKey) -> CryptoKeystoreResult<u32> {
    let previous_builder = super::v08::get_builder(name);
    let db_during_migration = Database::migration_connection(previous_builder, key).await?;
    let storage = db_during_migration.storage();
    let mut credentials = Vec::new();
    for key in storage.get_all_storage_keys::<StoredCredentialV36>().await? {
        match storage.get::<StoredCredentialV36>(&key).await {
            Ok(Some(credential)) => credentials.push(credential),
            Ok(None) => {}
            Err(err) => log::warn!("Dropping an unreadable IndexedDB v8 credential: {err}"),
        }
    }

    let collection_name = format!(
        "{collection_name}_new",
        collection_name = StoredCredentialV36::TABLE_NAME
    );

    Database::migration_transaction(db_during_migration, async |tx| {
        match tx {
            WasmStorageTransaction::Persistent { tx, cipher } => {
                let serializer = serde_wasm_bindgen::Serializer::json_compatible();
                let store = tx.object_store(&collection_name)?;
                // An interrupted upgrade can leave a previous copy here. Rebuild from the source store.
                store.clear()?.await?;
                for credential in credentials {
                    let key = &js_sys::Uint8Array::from(credential.public_key.as_slice()).into();
                    let js_value = credential.encrypt(cipher)?.serialize(&serializer)?;
                    store.put(&js_value, Some(key))?.await?;
                }
            }
            WasmStorageTransaction::InMemory { .. } => {
                // in memory transaction is transient and always initialized with the newest database version, so there
                // are no credentials to migrate.
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

/// Set up the builder for v9: drop the old credentials store and rename the staging one over it.
///
/// Only the v9 upgrade itself may use this. `remove_object_store` records the deletion on the
/// builder, and [`DatabaseBuilder::build`] replays every recorded deletion on every subsequent
/// upgrade. A later version which inherited this builder would therefore delete `mls_credentials`
/// -- by then the renamed store, holding every credential -- and, finding no staging store left to
/// rename over it, recreate it empty. Later versions inherit [`get_inheritable_builder`] instead.
pub(super) fn get_builder(name: &str) -> DatabaseBuilder {
    let collection_name = StoredCredentialV36::TABLE_NAME;
    let collection_name_with_prefix = &format!("{collection_name}_new",);

    super::v08::get_builder(name)
        .version(DB_VERSION_9)
        .remove_object_store(collection_name)
        .rename_object_store(collection_name_with_prefix, collection_name)
}

/// The v9 schema, for later versions to build on.
///
/// Describes the same end state as [`get_builder`] -- the staging store gone, `mls_credentials` in
/// its post-rename form -- but states it directly instead of deleting and renaming to reach it, so
/// that inheriting it cannot destroy data. See [`get_builder`] for why the two must differ.
pub(super) fn get_inheritable_builder(name: &str) -> DatabaseBuilder {
    let collection_name = StoredCredentialV36::TABLE_NAME;

    super::v08::get_builder(name)
        .version(DB_VERSION_9)
        // The staging store no longer exists under this name, so this only drops it from the
        // description. Recording the removal is harmless: `build` deletes only stores which are
        // actually present.
        .remove_object_store(&format!("{collection_name}_new"))
        // Replaces the definition v8 inherited for this name with the post-rename one.
        .add_object_store(super::v08::credentials_store(collection_name))
}
