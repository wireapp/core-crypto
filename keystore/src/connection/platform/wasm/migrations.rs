use crate::connection::platform::wasm::version_number;
use crate::connection::storage::{WasmEncryptedStorage, WasmStorageWrapper};
use crate::connection::KeystoreDatabaseConnection;
use crate::entities::{
    E2eiAcmeCA, E2eiCrl, E2eiEnrollment, E2eiIntermediateCert, E2eiRefreshToken, Entity, EntityBase, MlsCredential,
    MlsEncryptionKeyPair, MlsEpochEncryptionKeyPair, MlsHpkePrivateKey, MlsKeyPackage, MlsPendingMessage, MlsPskBundle,
    MlsSignatureKeyPair, PersistedMlsGroup, PersistedMlsPendingGroup, ProteusIdentity, ProteusPrekey, ProteusSession,
};
use crate::{CryptoKeystoreError, CryptoKeystoreResult};
use idb::builder::{DatabaseBuilder, IndexBuilder, ObjectStoreBuilder};
use idb::KeyPath;
use keystore_v_1_0_0::connection::KeystoreDatabaseConnection as KeystoreDatabaseConnectionV1_0_0;
use keystore_v_1_0_0::entities::{
    Entity as EntityV1_0_0, EntityFindParams as EntityFindParamsV1_0_0, MlsCredential as MlsCredentialV1_0_0,
};
use keystore_v_1_0_0::Connection as ConnectionV1_0_0;

/// This is called from a while loop. The `from` argument represents the version the migration is performed from.
/// The function will return the version number of the DB resulting from the migration.
///
/// To add a new migration, adjust the previous bottom match arm to return the current version,
///     add a new match arm below that matches on that version, perform the migration workload
///     and finally return `final_target`.
pub(crate) async fn migrate(from: u32, final_target: u32, name: &str, key: &str) -> CryptoKeystoreResult<u32> {
    const VERSION_NUMBER_V1_0_2: u32 = version_number(1, 0, 2, 0);
    match from {
        // The latest version that results from a migration must always map to "final_target"
        //      to ensure convergence of the while loop this is called from.
        0..=VERSION_NUMBER_V1_0_2 => {
            // The version passed into this function must be the same as the one returned by this match arm.
            // Will need to be adjusted once you add a new migration.
            migrate_to_post_v_1_0_2(name, key, final_target).await?;
            Ok(final_target)
        }
        _ => Err(CryptoKeystoreError::MigrationNotSupported(from)),
    }
}

/// Migrates from any old version to post 1.0.2 (unclear right now what number this will be).
/// Assumption: the entire storage fits into memory
async fn migrate_to_post_v_1_0_2(name: &str, key: &str, version: u32) -> CryptoKeystoreResult<()> {
    let old_storage = keystore_v_1_0_0::Connection::open_with_key(name, key).await?;

    // Get all "old" records and convert them
    // ! Assumption: the entire storage fits into memory
    let mut credentials = MlsCredential::convert_from_v_1_2_0_or_earlier(&old_storage).await?;
    old_storage.close().await?;

    // Now store all converted records in the new storage.
    // This will overwrite all previous entities in the DB.
    // Cannot use public API here because we would end in a never-ending loop
    let new_idb = get_builder(name, version).build().await?;
    let new_wrapper = WasmStorageWrapper::Persistent(new_idb);
    let mut new_storage = WasmEncryptedStorage::new(key, new_wrapper);

    new_storage
        .save(MlsCredential::COLLECTION_NAME, &mut credentials)
        .await?;

    new_storage.close()?;
    Ok(())
}

fn get_builder_v0(name: &str) -> DatabaseBuilder {
    let idb_builder = DatabaseBuilder::new(name)
        .version(0) // TODO use constant
        .add_object_store(
            ObjectStoreBuilder::new(MlsCredential::COLLECTION_NAME)
                .auto_increment(false)
                .add_index(IndexBuilder::new("id".into(), KeyPath::new_single("id")))
                .add_index(IndexBuilder::new("credential".into(), KeyPath::new_single("credential")).unique(true)),
        )
        .add_object_store(
            ObjectStoreBuilder::new(MlsSignatureKeyPair::COLLECTION_NAME)
                .auto_increment(false)
                .add_index(IndexBuilder::new(
                    "signature_scheme".into(),
                    KeyPath::new_single("signature_scheme"),
                ))
                .add_index(IndexBuilder::new("signature_pk".into(), KeyPath::new_single("pk"))),
        )
        .add_object_store(
            ObjectStoreBuilder::new(MlsHpkePrivateKey::COLLECTION_NAME)
                .auto_increment(false)
                .add_index(IndexBuilder::new("pk".into(), KeyPath::new_single("pk")).unique(true)),
        )
        .add_object_store(
            ObjectStoreBuilder::new(MlsEncryptionKeyPair::COLLECTION_NAME)
                .auto_increment(false)
                .add_index(IndexBuilder::new("pk".into(), KeyPath::new_single("pk")).unique(true)),
        )
        .add_object_store(
            ObjectStoreBuilder::new(MlsEpochEncryptionKeyPair::COLLECTION_NAME)
                .auto_increment(false)
                .add_index(IndexBuilder::new("id".into(), KeyPath::new_single("id")).unique(true)),
        )
        .add_object_store(
            ObjectStoreBuilder::new(MlsPskBundle::COLLECTION_NAME)
                .auto_increment(false)
                .add_index(IndexBuilder::new("psk_id".into(), KeyPath::new_single("psk_id")).unique(true)),
        )
        .add_object_store(
            ObjectStoreBuilder::new(MlsKeyPackage::COLLECTION_NAME)
                .auto_increment(false)
                .add_index(
                    IndexBuilder::new("keypackage_ref".into(), KeyPath::new_single("keypackage_ref")).unique(true),
                ),
        )
        .add_object_store(
            ObjectStoreBuilder::new(PersistedMlsGroup::COLLECTION_NAME)
                .auto_increment(false)
                .add_index(IndexBuilder::new("id".into(), KeyPath::new_single("id")).unique(true)),
        )
        .add_object_store(
            ObjectStoreBuilder::new(PersistedMlsPendingGroup::COLLECTION_NAME)
                .auto_increment(false)
                .add_index(IndexBuilder::new("id".into(), KeyPath::new_single("id")).unique(true)),
        )
        .add_object_store(
            ObjectStoreBuilder::new(MlsPendingMessage::COLLECTION_NAME)
                .auto_increment(false)
                .add_index(IndexBuilder::new("id".into(), KeyPath::new_single("id"))),
        )
        .add_object_store(
            ObjectStoreBuilder::new(E2eiEnrollment::COLLECTION_NAME)
                .auto_increment(false)
                .add_index(IndexBuilder::new("id".into(), KeyPath::new_single("id")).unique(true)),
        )
        .add_object_store(
            ObjectStoreBuilder::new(E2eiRefreshToken::COLLECTION_NAME)
                .auto_increment(false)
                .add_index(IndexBuilder::new("id".into(), KeyPath::new_single("id")).unique(true)),
        )
        .add_object_store(
            ObjectStoreBuilder::new(E2eiAcmeCA::COLLECTION_NAME)
                .auto_increment(false)
                .add_index(IndexBuilder::new("id".into(), KeyPath::new_single("id")).unique(true)),
        )
        .add_object_store(
            ObjectStoreBuilder::new(E2eiIntermediateCert::COLLECTION_NAME)
                .auto_increment(false)
                .add_index(IndexBuilder::new("ski_aki_pair".into(), KeyPath::new_single("ski_aki_pair")).unique(true)),
        )
        .add_object_store(
            ObjectStoreBuilder::new(E2eiCrl::COLLECTION_NAME)
                .auto_increment(false)
                .add_index(
                    IndexBuilder::new("distribution_point".into(), KeyPath::new_single("distribution_point"))
                        .unique(true),
                ),
        )
        .add_object_store(
            ObjectStoreBuilder::new(ProteusPrekey::COLLECTION_NAME)
                .auto_increment(false)
                .add_index(IndexBuilder::new("id".into(), KeyPath::new_single("id")).unique(true)),
        )
        .add_object_store(
            ObjectStoreBuilder::new(ProteusIdentity::COLLECTION_NAME)
                .auto_increment(false)
                .add_index(IndexBuilder::new("pk".into(), KeyPath::new_single("pk")).unique(true)),
        )
        .add_object_store(
            ObjectStoreBuilder::new(ProteusSession::COLLECTION_NAME)
                .auto_increment(false)
                .add_index(IndexBuilder::new("id".into(), KeyPath::new_single("id")).unique(true)),
        );
    #[cfg(feature = "idb-regression-test")]
    let idb_builder = idb_builder.add_object_store(ObjectStoreBuilder::new("regression_check").auto_increment(false));
    idb_builder
}

trait WasmMigrationExt: Entity<ConnectionType = KeystoreDatabaseConnection>
where
    Self: 'static,
{
    type EntityTypeV1_0_0: EntityV1_0_0<ConnectionType = KeystoreDatabaseConnectionV1_0_0>;

    async fn convert_from_v_1_2_0_or_earlier(connection: &ConnectionV1_0_0) -> CryptoKeystoreResult<Vec<Self>> {
        // We can use the v1 keystore because it didn't change between v1.0.0 and v1.0.2.
        // Further, v1.0.0 migrates automatically from any earlier version.
        let converted_records = connection
            .find_all::<Self::EntityTypeV1_0_0>(EntityFindParamsV1_0_0::default())
            .await?
            .iter()
            .map(|old_record| {
                let serialized = postcard::to_stdvec(old_record)?;
                postcard::from_bytes::<Self>(&serialized).map_err(Into::into)
            })
            .collect::<Result<Vec<Self>, CryptoKeystoreError>>()?;
        Ok(converted_records)
    }
}

impl WasmMigrationExt for MlsCredential {
    type EntityTypeV1_0_0 = MlsCredentialV1_0_0;
}
