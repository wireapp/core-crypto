//! This migration merges signature keypair and credential data
mod v5_entities;

use idb::builder::DatabaseBuilder;

use super::DB_VERSION_6;
use crate::{
    CryptoKeystoreResult, DatabaseKey,
    connection::idb_migration::legacy::{
        connection::Database,
        traits::{EntityBase as _, EntityDatabaseMutation as _},
    },
    migrations::historical::{StoredSignatureKeypair, V5Credential, V6Credential, migrate_to_new_credential},
};

/// Open IDB once with the new builder and close it, this will apply the update.
pub(super) async fn migrate(name: &str, key: &DatabaseKey) -> CryptoKeystoreResult<u32> {
    let previous_builder = super::v05::get_builder(name);
    let db_during_migration = Database::migration_connection(previous_builder, key).await?;
    let storage = db_during_migration.storage();

    let mut signature_keys = Vec::new();
    for key in storage.get_all_storage_keys::<StoredSignatureKeypair>().await? {
        match storage.get::<StoredSignatureKeypair>(&key).await {
            Ok(Some(keypair)) => signature_keys.push(keypair),
            Ok(None) => {}
            Err(err) => log::warn!("Skipping an unreadable IndexedDB v5 signature keypair: {err}"),
        }
    }

    // load everything into memory before editing anything, so we don't break the iteration due to mutation
    let mut v5_credentials = Vec::new();
    let mut credential_keys_to_delete = Vec::new();
    for key in storage.get_all_storage_keys::<V5Credential>().await? {
        match storage.get::<V5Credential>(&key).await {
            Ok(Some(credential)) => v5_credentials.push((key, credential)),
            // The IndexedDB wrapper also returns None for a stored null or undefined value.
            Ok(None) => credential_keys_to_delete.push(key),
            Err(err) => {
                // Credential conversion can commit before the database version changes.
                if let Ok(Some(_)) = storage.get::<V6Credential>(&key).await {
                    continue;
                }
                log::warn!("Dropping an unreadable IndexedDB v5 credential: {err}");
                credential_keys_to_delete.push(key);
            }
        }
    }

    Database::migration_transaction(db_during_migration, async |tx| {
        'credential: for (key, v5_credential) in v5_credentials {
            for signature_key in &signature_keys {
                if let Some(new_credential) = migrate_to_new_credential(&v5_credential, signature_key)? {
                    new_credential.save(tx).await?;
                    tx.delete::<V5Credential>(key).await?;
                    continue 'credential;
                }
            }
            log::warn!("Dropping an IndexedDB v5 credential with no matching signature keypair");
            credential_keys_to_delete.push(key);
        }

        for key in credential_keys_to_delete {
            tx.delete::<V5Credential>(key).await?;
        }

        Ok(())
    })
    .await?;

    let migrated_idb = get_builder(name).build().await?;
    let version = migrated_idb.version()?;
    migrated_idb.close();
    Ok(version)
}

/// Set up the builder for v6.
pub(super) fn get_builder(name: &str) -> DatabaseBuilder {
    super::v05::get_builder(name)
        .version(DB_VERSION_6)
        .remove_object_store(StoredSignatureKeypair::TABLE_NAME)
}
