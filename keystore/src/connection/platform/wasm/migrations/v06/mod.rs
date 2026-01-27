//! This migration merges signature keypair and credential data
mod v5_entities;

use std::collections::HashSet;

use idb::builder::DatabaseBuilder;

use super::DB_VERSION_6;
use crate::{
    CryptoKeystoreResult, Database, DatabaseKey,
    migrations::{StoredSignatureKeypair, V5Credential, migrate_to_new_credential},
    traits::{Entity as _, EntityBase as _, EntityDatabaseMutation as _},
};

/// Open IDB once with the new builder and close it, this will apply the update.
pub(super) async fn migrate(name: &str, key: &DatabaseKey) -> CryptoKeystoreResult<u32> {
    let previous_builder = super::v05::get_builder(name);
    let mut db_during_migration = Database::migration_connection(previous_builder, key).await?;
    let signature_keys = StoredSignatureKeypair::load_all(&mut db_during_migration).await?;
    let v5_credentials = V5Credential::load_all(&mut db_during_migration).await?;

    Database::migration_transaction(db_during_migration, async |tx| {
        let mut session_ids_to_clean_up = HashSet::<Vec<u8>>::new();
        'credential: for v5_credential in v5_credentials.iter() {
            for signature_key in signature_keys.iter() {
                if let Some(new_credential) = migrate_to_new_credential(v5_credential, signature_key)? {
                    new_credential.save(tx).await?;
                    super::delete_credential_by_session_id(tx, v5_credential.id.clone()).await?;
                    continue 'credential;
                }
            }
            session_ids_to_clean_up.insert(v5_credential.id.clone());
        }

        if !session_ids_to_clean_up.is_empty() {
            log::warn!("expected to migrate all v5 credentials");
            for session_id in session_ids_to_clean_up {
                super::delete_credential_by_session_id(tx, session_id).await?;
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

/// Set up the builder for v6.
pub(super) fn get_builder(name: &str) -> DatabaseBuilder {
    super::v05::get_builder(name)
        .version(DB_VERSION_6)
        .remove_object_store(StoredSignatureKeypair::COLLECTION_NAME)
}
