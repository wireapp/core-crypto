//! This migration deduplicates credentials and creates a new object store, "mls_credentials_new".

use idb::{
    KeyPath,
    builder::{IndexBuilder, ObjectStoreBuilder},
};

use super::{DB_VERSION_8, Metabuilder};
use crate::{
    CryptoKeystoreResult, Database, DatabaseKey,
    connection::FetchFromDatabase as _,
    entities::{EntityBase, EntityFindParams, PersistedMlsGroup, StoredCredential},
    migrations::{detect_duplicate_credentials, make_least_used_ciphersuite},
};

/// Open IDB once with the new builder and close it, this will apply the update.
pub(super) async fn migrate(name: &str, key: &DatabaseKey) -> CryptoKeystoreResult<u32> {
    let db_before_migration = Database::open(crate::ConnectionType::Persistent(name), key).await?;
    let persisted_mls_groups = db_before_migration
        .find_all::<PersistedMlsGroup>(EntityFindParams::default())
        .await?;
    let least_used_ciphersuite = make_least_used_ciphersuite(persisted_mls_groups)?;
    let credentials = db_before_migration
        .find_all::<StoredCredential>(EntityFindParams::default())
        .await?;
    let duplicates = detect_duplicate_credentials(&credentials);

    db_before_migration.new_transaction().await?;

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
                db_before_migration
                    .cred_delete_by_credential(cred_a.credential.clone())
                    .await?;
                db_before_migration
                    .cred_delete_by_credential(cred_b.credential.clone())
                    .await?;
            }
            Some(least_used_ciphersuite) => {
                let cred_to_delete = if least_used_ciphersuite == cred_a.ciphersuite {
                    cred_a.credential.clone()
                } else {
                    cred_b.credential.clone()
                };
                db_before_migration.cred_delete_by_credential(cred_to_delete).await?;
            }
        };
    }

    db_before_migration.commit_transaction().await?;
    db_before_migration.close().await?;

    let migrated_idb = get_builder(name).build().await?;
    let version = migrated_idb.version()?;
    migrated_idb.close();
    Ok(version)
}

/// Set up the builder for v8.
pub(super) fn get_builder(name: &str) -> Metabuilder {
    super::v7::get_builder(name).version(DB_VERSION_8).add_object_store(
        ObjectStoreBuilder::new(&format!(
            "{collection_name}_new",
            collection_name = StoredCredential::COLLECTION_NAME
        ))
        .auto_increment(false)
        .add_index(IndexBuilder::new("public_key".into(), KeyPath::new_single("public_key")).unique(true)),
    )
}
