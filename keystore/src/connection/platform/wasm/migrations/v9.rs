//! This migration queries all credentials from the credential store, inserts them into the new one, then removes the
//! old store and renames the new one.

use idb::builder::DatabaseBuilder;
use serde::Serialize as _;

use super::DB_VERSION_9;
use crate::{
    CryptoKeystoreResult, Database, DatabaseKey,
    connection::platform::wasm::WasmStorageTransaction,
    entities::StoredCredential,
    traits::{Encrypting as _, Entity as _, EntityBase as _},
};

/// Open IDB once with the new builder and close it, this will apply the update.
pub(super) async fn migrate(name: &str, key: &DatabaseKey) -> CryptoKeystoreResult<u32> {
    let previous_builder = super::v8::get_builder(name);
    let mut db_during_migration = Database::migration_connection(previous_builder, key).await?;
    let credentials = StoredCredential::load_all(&mut db_during_migration).await?;

    let collection_name = format!(
        "{collection_name}_new",
        collection_name = StoredCredential::COLLECTION_NAME
    );

    Database::migration_transaction(db_during_migration, async |tx| {
        match tx {
            WasmStorageTransaction::Persistent { tx, cipher } => {
                let serializer = serde_wasm_bindgen::Serializer::json_compatible();
                let store = tx.object_store(&collection_name)?;
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

/// Set up the builder for v9.
pub(super) fn get_builder(name: &str) -> DatabaseBuilder {
    let collection_name = StoredCredential::COLLECTION_NAME;
    let collection_name_with_prefix = &format!("{collection_name}_new",);

    super::v8::get_builder(name)
        .version(DB_VERSION_9)
        .remove_object_store(collection_name)
        .rename_object_store(collection_name_with_prefix, collection_name)
}
