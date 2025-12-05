mod v5_entities;

use idb::builder::DatabaseBuilder;

use super::DB_VERSION_6;
use crate::{
    CryptoKeystoreResult, Database, DatabaseKey,
    connection::FetchFromDatabase,
    entities::{EntityBase as _, EntityFindParams},
    migrations::{StoredSignatureKeypair, V5Credential, migrate_to_new_credential},
};

/// Open IDB once with the new builder and close it, this will apply the update.
pub(super) async fn migrate(name: &str, key: &DatabaseKey) -> CryptoKeystoreResult<u32> {
    let db_before_migration = Database::open(crate::ConnectionType::Persistent(name), key).await?;
    let signature_keys = db_before_migration
        .find_all::<StoredSignatureKeypair>(EntityFindParams::default())
        .await?;
    let v5_credentials = db_before_migration
        .find_all::<V5Credential>(EntityFindParams::default())
        .await?;

    db_before_migration.new_transaction().await?;

    for signature_key in signature_keys.iter() {
        for v5_credential in v5_credentials.iter() {
            if let Some(new_credential) = migrate_to_new_credential(v5_credential, signature_key)? {
                db_before_migration
                    .cred_delete_by_credential(v5_credential.credential.clone())
                    .await?;
                db_before_migration.save(new_credential).await?;
            }
        }
    }

    db_before_migration.commit_transaction().await?;
    db_before_migration.close().await?;

    let migrated_idb = get_builder(name).build().await?;
    let version = migrated_idb.version()?;
    migrated_idb.close();
    Ok(version)
}

/// Set up the builder for v6.
pub(super) fn get_builder(name: &str) -> DatabaseBuilder {
    super::v5::get_builder(name)
        .version(DB_VERSION_6)
        .remove_object_store(StoredSignatureKeypair::COLLECTION_NAME)
}
