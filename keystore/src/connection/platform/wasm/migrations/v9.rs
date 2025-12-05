//! This migration queries all credentials from the credential store, inserts them into the new one, then removes the
//! old store and renames the new one.

use idb::builder::DatabaseBuilder;
use serde::Serialize as _;

use super::DB_VERSION_9;
use crate::{
    CryptoKeystoreResult, Database, DatabaseKey,
    connection::platform::wasm::WasmStorageTransaction,
    entities::{Entity as _, EntityBase, StoredCredential},
};

/// Open IDB once with the new builder and close it, this will apply the update.
pub(super) async fn migrate(name: &str, key: &DatabaseKey) -> CryptoKeystoreResult<u32> {
    let db_before_migration = Database::open(crate::ConnectionType::Persistent(name), key).await?;
    let connection = db_before_migration.conn().await?;
    let credentials = connection
        .storage()
        .get_all::<StoredCredential>(StoredCredential::COLLECTION_NAME, None)
        .await?;

    let collection_name = format!(
        "{collection_name}_new",
        collection_name = StoredCredential::COLLECTION_NAME
    );

    db_before_migration.new_transaction().await?;
    let mut tx_creator = connection.conn().await;
    let mut tx = tx_creator.new_transaction(&[&collection_name]).await?;

    for mut credential in credentials {
        let serializer = serde_wasm_bindgen::Serializer::json_compatible();
        let key = &js_sys::Uint8Array::from(credential.public_key.as_slice()).into();
        match tx {
            WasmStorageTransaction::Persistent { ref mut tx, cipher } => {
                credential.encrypt(cipher)?;
                let js_value = credential.serialize(&serializer)?;
                let store = tx.object_store(&collection_name)?;
                store.put(&js_value, Some(key))?.await?;
            }
            WasmStorageTransaction::InMemory { .. } => {
                // in memory transaction is transient and always initialized with the newest database version, so there
                // are no credentials to migrate.
            }
        }
    }

    tx.commit_tx().await?;
    db_before_migration.close().await?;

    let migrated_idb = get_builder(name).build().await?;
    let version = migrated_idb.version()?;
    migrated_idb.close();
    Ok(version)
}

/// Set up the builder for v9.
pub(super) fn get_builder(name: &str) -> DatabaseBuilder {
    let collection_name = StoredCredential::COLLECTION_NAME;
    let collection_name_with_prefix = &format!("{collection_name}-new",);

    super::v8::get_builder(name)
        .version(DB_VERSION_9)
        .remove_object_store(collection_name)
        .rename_object_store(collection_name_with_prefix, collection_name)
}
