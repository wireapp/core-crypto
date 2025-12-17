mod v6_entities;

use idb::builder::DatabaseBuilder;

use super::DB_VERSION_7;
use crate::{
    CryptoKeystoreResult, Database, DatabaseKey,
    entities::{Entity as _, EntityFindParams, EntityTransactionExt as _, PersistedMlsGroup, StoredCredential},
    migrations::{V6Credential, make_ciphersuite_for_signature_scheme},
};

/// Open IDB once with the new builder and close it, this will apply the update.
pub(super) async fn migrate(name: &str, key: &DatabaseKey) -> CryptoKeystoreResult<u32> {
    let previous_builder = super::v6::get_builder(name);
    let mut db_during_migration = Database::migration_connection(previous_builder, key).await?;
    let persisted_mls_groups =
        PersistedMlsGroup::find_all(&mut db_during_migration, EntityFindParams::default()).await?;
    let ciphersuite_for_signature_scheme = make_ciphersuite_for_signature_scheme(persisted_mls_groups)?;
    let v6_credentials = V6Credential::find_all(&mut db_during_migration, EntityFindParams::default()).await?;

    Database::migration_transaction(db_during_migration, async |tx| {
        for v6_credential in v6_credentials {
            if let Some(ciphersuite) = ciphersuite_for_signature_scheme(v6_credential.signature_scheme) {
                let new_credential = StoredCredential {
                    ciphersuite,
                    session_id: v6_credential.session_id.clone(),
                    credential: v6_credential.credential.clone(),
                    created_at: v6_credential.created_at,
                    public_key: v6_credential.public_key.clone(),
                    private_key: v6_credential.private_key.clone(),
                };
                super::delete_credential_by_session_id(tx, v6_credential.session_id.clone()).await?;
                new_credential.save(tx).await?;
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

/// Set up the builder for v7.
pub(super) fn get_builder(name: &str) -> DatabaseBuilder {
    super::v6::get_builder(name).version(DB_VERSION_7)
}
