//! This migration deduplicates credentials and creates a new object store, "mls_credentials_new".

use idb::{
    KeyPath,
    builder::{DatabaseBuilder, IndexBuilder, ObjectStoreBuilder},
};

use super::{DB_VERSION_8, load_group_ciphersuites};
use crate::{
    CryptoKeystoreResult, DatabaseKey,
    connection::idb_migration::legacy::{connection::Database, traits::EntityBase as _},
    migrations::historical::{
        LegacyPersistedMlsGroup, StoredCredentialV36, detect_duplicate_credentials, make_least_used_ciphersuite,
    },
};

/// Open IDB once with the new builder and close it, this will apply the update.
pub(super) async fn migrate(name: &str, key: &DatabaseKey) -> CryptoKeystoreResult<u32> {
    let previous_builder = super::v07::get_builder(name);
    let db_during_migration = Database::migration_connection(previous_builder, key).await?;
    let storage = db_during_migration.storage();
    let (ciphersuites, group_keys_to_delete) = load_group_ciphersuites(storage).await?;
    let least_used_ciphersuite = make_least_used_ciphersuite(ciphersuites.into_iter().map(Ok))?;

    let mut credentials = Vec::new();
    let mut credential_keys_to_delete = Vec::new();
    for key in storage.get_all_storage_keys::<StoredCredentialV36>().await? {
        match storage.get::<StoredCredentialV36>(&key).await {
            Ok(Some(credential)) => credentials.push(credential),
            Ok(None) => credential_keys_to_delete.push(key),
            Err(err) => {
                log::warn!("Dropping an unreadable IndexedDB v7 credential: {err}");
                credential_keys_to_delete.push(key);
            }
        }
    }
    let duplicates = detect_duplicate_credentials(&credentials);

    Database::migration_transaction(db_during_migration, async |tx| {
        for key in group_keys_to_delete {
            tx.delete::<LegacyPersistedMlsGroup>(key).await?;
        }
        for key in credential_keys_to_delete {
            tx.delete::<StoredCredentialV36>(key).await?;
        }
        for (cred_a, cred_b) in duplicates.into_iter() {
            let least_used_ciphersuite = least_used_ciphersuite(cred_a.ciphersuite, cred_b.ciphersuite);
            match least_used_ciphersuite {
                None => {
                    // If the least used ciphersuite couldn't be determined, something in the data is not what we assume
                    //
                    // a) the duplicate doesn't form a pair of ciphersuites with a matching signature scheme (error in
                    // previous meta migration)
                    //
                    // b) both ciphersuites don't get used in any mls group
                    //
                    // In both cases, what we want to do is delete both credentials.
                    super::delete_credential_by_session_id(tx, cred_a.session_id.clone()).await?;
                    super::delete_credential_by_session_id(tx, cred_b.session_id.clone()).await?;
                }
                Some(least_used_ciphersuite) => {
                    let _cred_to_delete = if least_used_ciphersuite == cred_a.ciphersuite {
                        cred_a.credential.clone()
                    } else {
                        cred_b.credential.clone()
                    };
                    // Here, we'd like to delete the duplicate. However, we cannot reliably delete a single credential
                    // with the old schema. We don't need to handle duplicates anyway, since the old schema allowed just
                    // one credential per session (see test in `migrations/mod.rs`).
                }
            };
        }
        Ok(())
    })
    .await?;

    let migrated_idb = get_builder(name).build().await?;
    let version = migrated_idb.version()?;
    migrated_idb.close();
    Ok(version)
}

/// The credentials store as it looks from v9 onward: keyed externally by the credential's public
/// key, with a unique index on that key.
///
/// v8 creates it under a temporary name and v9 renames it over the old `mls_credentials`. Every
/// version from v9 on therefore has to describe the same store under its final name, so the
/// definition lives here rather than being spelled out at each site.
pub(super) fn credentials_store(store_name: &str) -> ObjectStoreBuilder {
    ObjectStoreBuilder::new(store_name)
        .auto_increment(false)
        .add_index(IndexBuilder::new("public_key".into(), KeyPath::new_single("public_key")).unique(true))
}

/// Set up the builder for v8.
pub(super) fn get_builder(name: &str) -> DatabaseBuilder {
    super::v07::get_builder(name)
        .version(DB_VERSION_8)
        .add_object_store(credentials_store(&format!(
            "{collection_name}_new",
            collection_name = StoredCredentialV36::TABLE_NAME
        )))
}
