mod v6_entities;

use idb::builder::DatabaseBuilder;

use super::DB_VERSION_7;
use crate::{
    CryptoKeystoreResult, Database, DatabaseKey,
    connection::FetchFromDatabase as _,
    entities::{EntityBase as _, EntityFindParams, EntityTransactionExt as _, PersistedMlsGroup, StoredCredential},
    migrations::{V6Credential, make_ciphersuite_for_signature_scheme},
};

/// Open IDB once with the new builder and close it, this will apply the update.
pub(super) async fn migrate(name: &str, key: &DatabaseKey) -> CryptoKeystoreResult<u32> {
    let db_before_migration = Database::open(crate::ConnectionType::Persistent(name), key).await?;
    let persisted_mls_groups = db_before_migration
        .find_all::<PersistedMlsGroup>(EntityFindParams::default())
        .await?;
    let ciphersuite_for_signature_scheme = make_ciphersuite_for_signature_scheme(persisted_mls_groups)?;
    let v6_credentials = db_before_migration
        .find_all::<V6Credential>(EntityFindParams::default())
        .await?;

    let connection = db_before_migration.conn().await?;
    let mut tx_creator = connection.conn().await;
    let tx = tx_creator
        .new_transaction(&[&StoredCredential::COLLECTION_NAME])
        .await?;

    for v6_credential in v6_credentials {
        if let Some(ciphersuite) = ciphersuite_for_signature_scheme(v6_credential.signature_scheme) {
            let new_credential = StoredCredential {
                ciphersuite,
                id: v6_credential.id.clone(),
                credential: v6_credential.credential.clone(),
                created_at: v6_credential.created_at,
                public_key: v6_credential.public_key.clone(),
                secret_key: v6_credential.secret_key.clone(),
            };
            new_credential.save(&tx).await?;
            super::delete_credential_by_value(&tx, v6_credential.credential.clone()).await?;
        }
    }

    db_before_migration.commit_transaction().await?;
    db_before_migration.close().await?;

    let migrated_idb = get_builder(name).build().await?;
    let version = migrated_idb.version()?;
    migrated_idb.close();
    Ok(version)
}

/// Set up the builder for v7.
pub(super) fn get_builder(name: &str) -> DatabaseBuilder {
    super::v6::get_builder(name).version(DB_VERSION_7)
}
