mod v6_entities;

use super::{DB_VERSION_7, Metabuilder};
use crate::{
    CryptoKeystoreResult, Database, DatabaseKey,
    connection::FetchFromDatabase,
    entities::{Entity, EntityFindParams, StoredCredential},
    migrations::{V6Credential, ciphersuites_for_signature_scheme},
};

/// Open IDB once with the new builder and close it, this will apply the update.
pub(super) async fn migrate(name: &str, key: &DatabaseKey) -> CryptoKeystoreResult<u32> {
    let db_before_migration = Database::open(crate::ConnectionType::Persistent(name), key).await?;
    let v6_credentials = db_before_migration
        .find_all::<V6Credential>(EntityFindParams::default())
        .await?;

    db_before_migration.new_transaction().await?;

    // we duplicate the credential for each possible match of the ciphersuite on the basis
    // that it minimizes harm to have some extra pointless credentials in the DB rather than
    // having the proper credential absent
    for v6_credential in v6_credentials {
        for ciphersuite in ciphersuites_for_signature_scheme(v6_credential.signature_scheme) {
            let new_credential = StoredCredential {
                ciphersuite,
                id: v6_credential.id.clone(),
                credential: v6_credential.credential.clone(),
                created_at: v6_credential.created_at,
                public_key: v6_credential.public_key.clone(),
                secret_key: v6_credential.secret_key.clone(),
            };
            db_before_migration.save(new_credential).await?;
        }
        db_before_migration
            .remove::<V6Credential, _>(v6_credential.id_raw())
            .await?;
    }

    db_before_migration.commit_transaction().await?;
    db_before_migration.close().await?;

    let migrated_idb = get_builder(name).build().await?;
    let version = migrated_idb.version()?;
    migrated_idb.close();
    Ok(version)
}

/// Set up the builder for v7.
pub(super) fn get_builder(name: &str) -> Metabuilder {
    super::v6::get_builder(name).version(DB_VERSION_7)
}
