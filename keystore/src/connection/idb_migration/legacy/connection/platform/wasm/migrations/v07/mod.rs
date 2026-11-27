mod v6_entities;

use idb::builder::DatabaseBuilder;

use super::{DB_VERSION_7, load_group_ciphersuites};
use crate::{
    CryptoKeystoreResult, DatabaseKey,
    connection::idb_migration::legacy::{connection::Database, traits::EntityDatabaseMutation as _},
    migrations::historical::{
        LegacyPersistedMlsGroup, StoredCredentialV36, V6Credential,
        make_ciphersuite_for_signature_scheme_from_ciphersuites,
    },
};

/// Open IDB once with the new builder and close it, this will apply the update.
pub(super) async fn migrate(name: &str, key: &DatabaseKey) -> CryptoKeystoreResult<u32> {
    let previous_builder = super::v06::get_builder(name);
    let db_during_migration = Database::migration_connection(previous_builder, key).await?;
    let storage = db_during_migration.storage();

    let (ciphersuites, group_keys_to_delete) = load_group_ciphersuites(storage).await?;
    let ciphersuite_for_signature_scheme =
        make_ciphersuite_for_signature_scheme_from_ciphersuites(ciphersuites.into_iter().map(Ok))?;

    let mut v6_credentials = Vec::new();
    let mut credential_keys_to_delete = Vec::new();
    for key in storage.get_all_storage_keys::<V6Credential>().await? {
        match storage.get::<V6Credential>(&key).await {
            Ok(Some(credential)) => v6_credentials.push((key, credential)),
            Ok(None) => credential_keys_to_delete.push(key),
            Err(err) => {
                log::warn!("Dropping an unreadable IndexedDB v6 credential: {err}");
                credential_keys_to_delete.push(key);
            }
        }
    }

    Database::migration_transaction(db_during_migration, async |tx| {
        for (key, v6_credential) in v6_credentials {
            if let Some(ciphersuite) = ciphersuite_for_signature_scheme(v6_credential.signature_scheme) {
                let new_credential = StoredCredentialV36 {
                    ciphersuite,
                    session_id: v6_credential.session_id.clone(),
                    credential: v6_credential.credential.clone(),
                    created_at: v6_credential.created_at,
                    public_key: v6_credential.public_key.clone(),
                    private_key: v6_credential.private_key.clone(),
                };
                super::delete_credential_by_session_id(tx, v6_credential.session_id.clone()).await?;
                new_credential.save(tx).await?;
            } else {
                log::warn!("Dropping an IndexedDB v6 credential whose ciphersuite could not be determined");
                credential_keys_to_delete.push(key);
            }
        }
        for key in credential_keys_to_delete {
            tx.delete::<V6Credential>(key).await?;
        }
        for key in group_keys_to_delete {
            tx.delete::<LegacyPersistedMlsGroup>(key).await?;
        }
        Ok(())
    })
    .await?;

    let migrated_idb = get_builder(name).build().await?;
    let version = migrated_idb.version()?;
    migrated_idb.close();
    Ok(version)
}

/// Set up the builder for v7.
pub(super) fn get_builder(name: &str) -> DatabaseBuilder {
    super::v06::get_builder(name).version(DB_VERSION_7)
}
