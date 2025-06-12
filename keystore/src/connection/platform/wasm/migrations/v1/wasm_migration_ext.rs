use super::super::keystore_v_1_0_0::{
    CryptoKeystoreError as CryptoKeystoreErrorV1_0_0,
    connection::KeystoreDatabaseConnection as KeystoreDatabaseConnectionV1_0_0,
    entities::{
        E2eiAcmeCA as E2eiAcmeCAV1_0_0, E2eiCrl as E2eiCrlV1_0_0, E2eiEnrollment as E2eiEnrollmentV1_0_0,
        E2eiIntermediateCert as E2eiIntermediateCertV1_0_0, E2eiRefreshToken as E2eiRefreshTokenV1_0_0,
        Entity as EntityV1_0_0, MlsCredential as MlsCredentialV1_0_0,
        MlsEncryptionKeyPair as MlsEncryptionKeyPairV1_0_0,
        MlsEpochEncryptionKeyPair as MlsEpochEncryptionKeyPairV1_0_0, MlsHpkePrivateKey as MlsHpkePrivateKeyV1_0_0,
        MlsKeyPackage as MlsKeyPackageV1_0_0, MlsPendingMessage as MlsPendingMessageV1_0_0,
        MlsPskBundle as MlsPskBundleV1_0_0, MlsSignatureKeyPair as MlsSignatureKeyPairV1_0_0,
        PersistedMlsGroup as PersistedMlsGroupV1_0_0, PersistedMlsPendingGroup as PersistedMlsPendingGroupV1_0_0,
        ProteusIdentity as ProteusIdentityV1_0_0, ProteusPrekey as ProteusPrekeyV1_0_0,
        ProteusSession as ProteusSessionV1_0_0, UniqueEntity as UniqueEntityV1_0_0,
    },
};
use crate::{
    CryptoKeystoreError, CryptoKeystoreResult,
    connection::KeystoreDatabaseConnection,
    entities::{
        E2eiAcmeCA, E2eiCrl, E2eiEnrollment, E2eiIntermediateCert, E2eiRefreshToken, Entity, MlsCredential,
        MlsEncryptionKeyPair, MlsEpochEncryptionKeyPair, MlsHpkePrivateKey, MlsKeyPackage, MlsPendingMessage,
        MlsPskBundle, MlsSignatureKeyPair, PersistedMlsGroup, PersistedMlsPendingGroup, ProteusIdentity, ProteusPrekey,
        ProteusSession, UniqueEntity,
    },
};

pub(super) trait WasmMigrationExt: Entity<ConnectionType = KeystoreDatabaseConnection>
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

pub(super) trait WasmMigrationUniqueExt: UniqueEntity<ConnectionType = KeystoreDatabaseConnection>
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
