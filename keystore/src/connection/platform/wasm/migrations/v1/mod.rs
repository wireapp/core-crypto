mod wasm_migration_ext;

use idb::{Factory, TransactionMode};
use serde::Serialize as _;

use super::DB_VERSION_1;
use crate::{
    CryptoKeystoreError, CryptoKeystoreResult,
    connection::storage::{WasmEncryptedStorage, WasmStorageWrapper},
    entities::{
        E2eiAcmeCA, E2eiCrl, E2eiEnrollment, E2eiIntermediateCert, E2eiRefreshToken, Entity as _, EntityBase as _,
        MlsCredential, MlsEncryptionKeyPair, MlsEpochEncryptionKeyPair, MlsHpkePrivateKey, MlsKeyPackage,
        MlsPendingMessage, MlsPskBundle, MlsSignatureKeyPair, PersistedMlsGroup, PersistedMlsPendingGroup,
        ProteusIdentity, ProteusPrekey, ProteusSession,
    },
};
use wasm_migration_ext::{WasmMigrationExt as _, WasmMigrationUniqueExt as _};

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
            let old_storage = super::keystore_v_1_0_0::Connection::open_with_key($name, $key).await?;
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
            let idb_during_migration = super::v0::get_builder($name).build().await?;
            let stores = idb_during_migration.store_names();
            let transaction = idb_during_migration.transaction(&stores, TransactionMode::ReadWrite)?;
            let wrapper_during_migration = WasmStorageWrapper::Persistent(idb_during_migration);
            let storage_during_migration = WasmEncryptedStorage::new_with_pre_v4_key($key, wrapper_during_migration);
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
            let version = idb.version()?;
            idb.close();

            Ok(version)
        }
    };
}

/// Migrates from any old DB version to DB version 1.
///
/// _**Assumption**_: the entire storage fits into memory
pub(super) async fn migrate(name: &str, key: &str) -> CryptoKeystoreResult<u32> {
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
