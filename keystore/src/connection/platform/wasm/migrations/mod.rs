pub mod keystore_v_1_0_0;

use crate::connection::KeystoreDatabaseConnection;
use crate::connection::storage::{WasmEncryptedStorage, WasmStorageWrapper};
use crate::entities::{
    ConsumerData, E2eiAcmeCA, E2eiCrl, E2eiEnrollment, E2eiIntermediateCert, E2eiRefreshToken, Entity, EntityBase,
    MlsBufferedCommit, MlsCredential, MlsEncryptionKeyPair, MlsEpochEncryptionKeyPair, MlsHpkePrivateKey,
    MlsKeyPackage, MlsPendingMessage, MlsPskBundle, MlsSignatureKeyPair, PersistedMlsGroup, PersistedMlsPendingGroup,
    ProteusIdentity, ProteusPrekey, ProteusSession, UniqueEntity,
};
use crate::{CryptoKeystoreError, CryptoKeystoreResult};
use idb::builder::{DatabaseBuilder, IndexBuilder, ObjectStoreBuilder};
use idb::{Database, Factory, KeyPath, TransactionMode};
use keystore_v_1_0_0::CryptoKeystoreError as CryptoKeystoreErrorV1_0_0;
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
use serde::ser::Serialize;

const fn db_version_number(counter: u32) -> u32 {
    // When the DB version was tied to core crypto, the version counter was the sum of 10_000_000
    // for a major version, 1_000 for a patch version. I.e., the number for v1.0.2 was:
    const VERSION_1_0_2: u32 = 10_000_000 + 2_000;
    // From post v1.0.2, we will just increment whenever we need a DB migration.
    VERSION_1_0_2 + counter
}

const DB_VERSION_0: u32 = db_version_number(0);
const DB_VERSION_1: u32 = db_version_number(1);
const DB_VERSION_2: u32 = db_version_number(2);
const DB_VERSION_3: u32 = db_version_number(3);

/// Open an existing idb database with the given name and key, and migrate it if needed.
pub(crate) async fn open_and_migrate(name: &str, key: &str) -> CryptoKeystoreResult<Database> {
    /// Increment when adding a new migration.
    const TARGET_VERSION: u32 = DB_VERSION_3;
    let factory = Factory::new()?;

    let open_existing = factory.open(name, None)?;
    let existing_db = open_existing.await?;
    let mut version = existing_db.version()?;
    if version == TARGET_VERSION {
        // Migration is not needed, just return existing db
        Ok(existing_db)
    } else {
        // Migration is needed
        existing_db.close();

        while version < TARGET_VERSION {
            version = do_migration_step(version, name, key).await?;
        }

        let open_request = factory.open(name, Some(TARGET_VERSION))?;
        open_request.await.map_err(Into::into)
    }
}

/// The `from` argument represents the version the migration is performed from the function will
/// return the version number of the DB resulting from the migration.
///
/// To add a new migration, add a new match arm below the latest one.
/// It must match on the version it migrates from, and call a function that performs the migration
/// workload, which returns the version it migrates to, which is the same value as TARGET_VERSION in
/// the function above at the time the migration is added.
///
/// However, do not use the constant but hardcode the value into the function.
/// This way it will keep working once a new migration is added after it.
async fn do_migration_step(from: u32, name: &str, key: &str) -> CryptoKeystoreResult<u32> {
    match from {
        // The version that results from the latest migration must match TARGET_VERSION
        //      to ensure convergence of the while loop this is called from.
        0..=DB_VERSION_0 => migrate_to_version_1(name, key).await,
        DB_VERSION_1 => migrate_to_version_2(name).await,
        DB_VERSION_2 => migrate_to_version_3(name).await,
        _ => Err(CryptoKeystoreError::MigrationNotSupported(from)),
    }
}

/// Open IDB once with the new builder and close it, this will add the new object store.
async fn migrate_to_version_3(name: &str) -> CryptoKeystoreResult<u32> {
    let migrated_idb = get_builder_v3(name).build().await?;
    migrated_idb.close();
    Ok(DB_VERSION_3)
}

/// Add a new object store for the MlsBufferedCommit struct.
fn get_builder_v3(name: &str) -> DatabaseBuilder {
    let previous_builder = get_builder_v2(name);
    previous_builder.version(DB_VERSION_3).add_object_store(
        ObjectStoreBuilder::new(MlsBufferedCommit::COLLECTION_NAME)
            .auto_increment(false)
            .add_index(
                IndexBuilder::new("conversation_id".into(), KeyPath::new_single("conversation_id")).unique(true),
            ),
    )
}

/// Open IDB once with the new builder and close it, this will add the new object store.
async fn migrate_to_version_2(name: &str) -> CryptoKeystoreResult<u32> {
    let migrated_idb = get_builder_v2(name).build().await?;
    migrated_idb.close();
    Ok(DB_VERSION_2)
}

/// Add a new object store for the ConsumerData struct.
fn get_builder_v2(name: &str) -> DatabaseBuilder {
    let previous_builder = get_builder_v0(name);
    previous_builder.version(DB_VERSION_2).add_object_store(
        ObjectStoreBuilder::new(ConsumerData::COLLECTION_NAME)
            .auto_increment(false)
            .add_index(IndexBuilder::new("id".into(), KeyPath::new_single("id")).unique(true)),
    )
}

/// With the current feature set of stable rust macros, we're not aware how to construct an
/// identifier for each entity inside the macro.
///
/// We need it for a variable to store the conversion result.
/// So we have to take an identifier for each entity as an argument.
/// Can be done better once [concat_idents] is stabilized, or we can use tuple indexing
/// when ${index()} is stabilized (https://github.com/rust-lang/rust/pull/122808).
macro_rules! migrate_entities_to_version_1 {
    ($name:expr, $key:expr, [ $( ($records:ident, $entity:ty) ),* ]) => {
        {

            let old_storage = keystore_v_1_0_0::Connection::open_with_key($name, $key).await?;
            let mut old_connection = old_storage.borrow_conn().await?;

            // A tuple of vectors containing records of each entity.
            // See docstring. Here, alternatively, we will be able construct an identifier for each
            // entity or use tuple indexing below once one of the required language features is
            // stable.
            let converted_collections = ( $(
                <$entity>::convert_to_db_version_1(&mut old_connection).await?,
            )* );

            drop(old_connection);
            old_storage.close().await?;

            // First open the new DB with DB_VERSION_0 – we only want to increment the version
            // counter once the migration is complete.
            let idb_during_migration = get_builder_v0($name).build().await?;
            let stores = idb_during_migration.store_names();
            let transaction = idb_during_migration.transaction(&stores, TransactionMode::ReadWrite)?;
            let wrapper_during_migration = WasmStorageWrapper::Persistent(idb_during_migration);
            let storage_during_migration = WasmEncryptedStorage::new($key, wrapper_during_migration);
            let serializer = serde_wasm_bindgen::Serializer::json_compatible();

            // See docstring. Here, alternatively, we'd use the identifiers constructed above for
            // each entity or use tuple indexing once one of the required language features is
            // stable.
            let ( $( $records, )* ) = converted_collections;

            $(
                let store = transaction.object_store(<$entity>::COLLECTION_NAME)?;
                for mut record in $records {
                    let key = record.id()?;
                    record.encrypt(&storage_during_migration.cipher)?;
                    let js_value = record.serialize(&serializer)?;
                    let request = store.put(&js_value, Some(&key))?;
                    request.await?;
                }
            )*

            let result = transaction.await?;

            storage_during_migration.close()?;

            if !result.is_committed() {
                return Err(CryptoKeystoreError::MigrationFailed);
            }

            // The migration is complete and the version counter can be incremented.
            let factory = Factory::new()?;
            let open_request = factory.open($name, Some(DB_VERSION_1))?;
            let idb = open_request.await?;
            idb.close();

            Ok(DB_VERSION_1)
        }
    };
}

/// Migrates from any old DB version to DB version 1.
///
/// _**Assumption**_: the entire storage fits into memory
async fn migrate_to_version_1(name: &str, key: &str) -> CryptoKeystoreResult<u32> {
    migrate_entities_to_version_1!(
        name,
        key,
        [
            (identifier_01, MlsCredential),
            (identifier_02, MlsSignatureKeyPair),
            (identifier_03, MlsHpkePrivateKey),
            (identifier_04, MlsEncryptionKeyPair),
            (identifier_05, MlsEpochEncryptionKeyPair),
            (identifier_06, MlsPskBundle),
            (identifier_07, MlsKeyPackage),
            (identifier_08, PersistedMlsGroup),
            (identifier_09, PersistedMlsPendingGroup),
            (identifier_10, MlsPendingMessage),
            (identifier_11, E2eiEnrollment),
            (identifier_12, E2eiRefreshToken),
            (identifier_13, E2eiAcmeCA),
            (identifier_14, E2eiIntermediateCert),
            (identifier_15, E2eiCrl),
            (identifier_16, ProteusPrekey),
            (identifier_17, ProteusIdentity),
            (identifier_18, ProteusSession)
        ]
    )
}

fn get_builder_v0(name: &str) -> DatabaseBuilder {
    let idb_builder = DatabaseBuilder::new(name)
        .version(DB_VERSION_0)
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
