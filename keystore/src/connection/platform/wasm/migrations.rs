use crate::connection::platform::wasm::version_number;
use crate::connection::storage::{WasmEncryptedStorage, WasmStorageWrapper};
use crate::connection::KeystoreDatabaseConnection;
use crate::entities::{
    E2eiAcmeCA, E2eiCrl, E2eiEnrollment, E2eiIntermediateCert, E2eiRefreshToken, Entity, EntityBase, MlsCredential,
    MlsEncryptionKeyPair, MlsEpochEncryptionKeyPair, MlsHpkePrivateKey, MlsKeyPackage, MlsPendingMessage, MlsPskBundle,
    MlsSignatureKeyPair, PersistedMlsGroup, PersistedMlsPendingGroup, ProteusIdentity, ProteusPrekey, ProteusSession,
    UniqueEntity,
};
use crate::{CryptoKeystoreError, CryptoKeystoreResult};
use idb::builder::{DatabaseBuilder, IndexBuilder, ObjectStoreBuilder};
use idb::KeyPath;
use keystore_v_1_0_0::connection::KeystoreDatabaseConnection as KeystoreDatabaseConnectionV1_0_0;
use keystore_v_1_0_0::entities::{
    E2eiAcmeCA as E2eiAcmeCAV1_0_0, E2eiCrl as E2eiCrlV1_0_0, E2eiEnrollment as E2eiEnrollmentV1_0_0,
    E2eiIntermediateCert as E2eiIntermediateCertV1_0_0, E2eiRefreshToken as E2eiRefreshTokenV1_0_0,
    Entity as EntityV1_0_0, MlsCredential as MlsCredentialV1_0_0, MlsEncryptionKeyPair as MlsEncryptionKeyPairV1_0_0,
    MlsEpochEncryptionKeyPair as MlsEpochEncryptionKeyPairV1_0_0, MlsHpkePrivateKey as MlsHpkePrivateKeyV1_0_0,
    MlsKeyPackage as MlsKeyPackageV1_0_0, MlsPendingMessage as MlsPendingMessageV1_0_0,
    MlsPskBundle as MlsPskBundleV1_0_0, MlsSignatureKeyPair as MlsSignatureKeyPairV1_0_0,
    PersistedMlsGroup as PersistedMlsGroupV1_0_0, PersistedMlsPendingGroup as PersistedMlsPendingGroupV1_0_0,
    ProteusIdentity as ProteusIdentityV1_0_0, ProteusPrekey as ProteusPrekeyV1_0_0,
    ProteusSession as ProteusSessionV1_0_0, UniqueEntity as UniqueEntityV1_0_0,
};
use keystore_v_1_0_0::CryptoKeystoreError as CryptoKeystoreErrorV1_0_0;

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
    let mut old_connection = old_storage.borrow_conn().await?;

    // Get all "old" records and convert them
    // ! Assumption: the entire storage fits into memory
    let mut credentials = MlsCredential::convert_to_db_version_1(&mut old_connection).await?;
    let mut signature_keys = MlsSignatureKeyPair::convert_to_db_version_1(&mut old_connection).await?;
    let mut hpke_keys = MlsHpkePrivateKey::convert_to_db_version_1(&mut old_connection).await?;
    let mut encryption_keys = MlsEncryptionKeyPair::convert_to_db_version_1(&mut old_connection).await?;
    let mut epoch_encryption_keys = MlsEpochEncryptionKeyPair::convert_to_db_version_1(&mut old_connection).await?;
    let mut psk_bundles = MlsPskBundle::convert_to_db_version_1(&mut old_connection).await?;
    let mut key_packages = MlsKeyPackage::convert_to_db_version_1(&mut old_connection).await?;
    let mut groups = PersistedMlsGroup::convert_to_db_version_1(&mut old_connection).await?;
    let mut pending_groups = PersistedMlsPendingGroup::convert_to_db_version_1(&mut old_connection).await?;
    let mut pending_messages = MlsPendingMessage::convert_to_db_version_1(&mut old_connection).await?;
    let mut e2ei_enrollments = E2eiEnrollment::convert_to_db_version_1(&mut old_connection).await?;
    let mut e2ei_tokens = E2eiRefreshToken::convert_to_db_version_1(&mut old_connection).await?;
    let mut e2ei_acme_cas = E2eiAcmeCA::convert_to_db_version_1(&mut old_connection).await?;
    let mut e2ei_intermediates = E2eiIntermediateCert::convert_to_db_version_1(&mut old_connection).await?;
    let mut e2ei_crls = E2eiCrl::convert_to_db_version_1(&mut old_connection).await?;
    let mut proteus_prekeys = ProteusPrekey::convert_to_db_version_1(&mut old_connection).await?;
    let mut proteus_identities = ProteusIdentity::convert_to_db_version_1(&mut old_connection).await?;
    let mut proteus_sessions = ProteusSession::convert_to_db_version_1(&mut old_connection).await?;
    // Fetching old records finished.
    drop(old_connection);
    old_storage.close().await?;

    // Create new storage. Cannot use public API here because we would end in a never-ending loop
    let new_idb = get_builder(name, version).build().await?;
    let new_wrapper = WasmStorageWrapper::Persistent(new_idb);
    let mut new_storage = WasmEncryptedStorage::new(key, new_wrapper);
    // Now store all converted records in the new storage.
    // This will overwrite all previous entities in the DB.
    new_storage
        .save(MlsCredential::COLLECTION_NAME, &mut credentials)
        .await?;
    new_storage
        .save(MlsSignatureKeyPair::COLLECTION_NAME, &mut signature_keys)
        .await?;
    new_storage
        .save(MlsHpkePrivateKey::COLLECTION_NAME, &mut hpke_keys)
        .await?;
    new_storage
        .save(MlsEncryptionKeyPair::COLLECTION_NAME, &mut encryption_keys)
        .await?;
    new_storage
        .save(MlsEpochEncryptionKeyPair::COLLECTION_NAME, &mut epoch_encryption_keys)
        .await?;
    new_storage
        .save(MlsPskBundle::COLLECTION_NAME, &mut psk_bundles)
        .await?;
    new_storage
        .save(MlsKeyPackage::COLLECTION_NAME, &mut key_packages)
        .await?;
    new_storage
        .save(PersistedMlsGroup::COLLECTION_NAME, &mut groups)
        .await?;
    new_storage
        .save(PersistedMlsPendingGroup::COLLECTION_NAME, &mut pending_groups)
        .await?;
    new_storage
        .save(MlsPendingMessage::COLLECTION_NAME, &mut pending_messages)
        .await?;
    new_storage
        .save(E2eiEnrollment::COLLECTION_NAME, &mut e2ei_enrollments)
        .await?;
    new_storage
        .save(E2eiRefreshToken::COLLECTION_NAME, &mut e2ei_tokens)
        .await?;
    new_storage
        .save(E2eiAcmeCA::COLLECTION_NAME, &mut e2ei_acme_cas)
        .await?;
    new_storage
        .save(E2eiIntermediateCert::COLLECTION_NAME, &mut e2ei_intermediates)
        .await?;
    new_storage.save(E2eiCrl::COLLECTION_NAME, &mut e2ei_crls).await?;
    new_storage
        .save(ProteusPrekey::COLLECTION_NAME, &mut proteus_prekeys)
        .await?;
    new_storage
        .save(ProteusIdentity::COLLECTION_NAME, &mut proteus_identities)
        .await?;
    new_storage
        .save(ProteusSession::COLLECTION_NAME, &mut proteus_sessions)
        .await?;
    // Migration finished
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

    async fn convert_to_db_version_1(
        connection: &mut KeystoreDatabaseConnectionV1_0_0,
    ) -> CryptoKeystoreResult<Vec<Self>> {
        // We can use the v1 keystore because it didn't change between v1.0.0 and v1.0.2.
        // Further, v1.0.0 migrates automatically from any earlier version.
        let converted_records = connection
            .storage()
            .get_all::<Self::EntityTypeV1_0_0>(Self::COLLECTION_NAME, None)
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

trait WasmMigrationUniqueExt: UniqueEntity<ConnectionType = KeystoreDatabaseConnection>
where
    Self: 'static,
{
    type EntityTypeV1_0_0: UniqueEntityV1_0_0<ConnectionType = KeystoreDatabaseConnectionV1_0_0>;

    async fn convert_to_db_version_1(
        connection: &mut KeystoreDatabaseConnectionV1_0_0,
    ) -> CryptoKeystoreResult<Vec<Self>> {
        let old_record_result = Self::EntityTypeV1_0_0::find_unique(connection).await;
        match old_record_result {
            Ok(old_record) => {
                let serialized = postcard::to_stdvec(&old_record)?;
                let new_record = postcard::from_bytes::<Self>(&serialized)?;
                Ok(vec![new_record])
            }
            // When it doesn't exist, it doesn't need conversion.
            Err(CryptoKeystoreErrorV1_0_0::NotFound(..)) => Ok(vec![]),
            Err(e) => Err(e)?,
        }
    }
}

impl WasmMigrationExt for E2eiEnrollment {
    type EntityTypeV1_0_0 = E2eiEnrollmentV1_0_0;
}

impl WasmMigrationUniqueExt for E2eiRefreshToken {
    type EntityTypeV1_0_0 = E2eiRefreshTokenV1_0_0;
}

impl WasmMigrationUniqueExt for E2eiAcmeCA {
    type EntityTypeV1_0_0 = E2eiAcmeCAV1_0_0;
}

impl WasmMigrationExt for MlsCredential {
    type EntityTypeV1_0_0 = MlsCredentialV1_0_0;
}

impl WasmMigrationExt for MlsSignatureKeyPair {
    type EntityTypeV1_0_0 = MlsSignatureKeyPairV1_0_0;
}

impl WasmMigrationExt for MlsHpkePrivateKey {
    type EntityTypeV1_0_0 = MlsHpkePrivateKeyV1_0_0;
}

impl WasmMigrationExt for MlsEncryptionKeyPair {
    type EntityTypeV1_0_0 = MlsEncryptionKeyPairV1_0_0;
}

impl WasmMigrationExt for MlsEpochEncryptionKeyPair {
    type EntityTypeV1_0_0 = MlsEpochEncryptionKeyPairV1_0_0;
}

impl WasmMigrationExt for MlsPskBundle {
    type EntityTypeV1_0_0 = MlsPskBundleV1_0_0;
}

impl WasmMigrationExt for MlsKeyPackage {
    type EntityTypeV1_0_0 = MlsKeyPackageV1_0_0;
}

impl WasmMigrationExt for PersistedMlsGroup {
    type EntityTypeV1_0_0 = PersistedMlsGroupV1_0_0;
}

impl WasmMigrationExt for PersistedMlsPendingGroup {
    type EntityTypeV1_0_0 = PersistedMlsPendingGroupV1_0_0;
}

impl WasmMigrationExt for MlsPendingMessage {
    type EntityTypeV1_0_0 = MlsPendingMessageV1_0_0;
}

impl WasmMigrationExt for E2eiCrl {
    type EntityTypeV1_0_0 = E2eiCrlV1_0_0;
}

impl WasmMigrationExt for E2eiIntermediateCert {
    type EntityTypeV1_0_0 = E2eiIntermediateCertV1_0_0;
}

impl WasmMigrationExt for ProteusSession {
    type EntityTypeV1_0_0 = ProteusSessionV1_0_0;
}

impl WasmMigrationExt for ProteusIdentity {
    type EntityTypeV1_0_0 = ProteusIdentityV1_0_0;
}

impl WasmMigrationExt for ProteusPrekey {
    type EntityTypeV1_0_0 = ProteusPrekeyV1_0_0;
}
