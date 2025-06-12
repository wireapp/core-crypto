use aes_gcm::KeyInit as _;
use idb::{Factory, TransactionMode};
use serde::Serialize as _;
use sha2::Digest as _;

use super::{DB_VERSION_3, DB_VERSION_4, pre_v4};
use crate::{
    CryptoKeystoreError, CryptoKeystoreResult, DatabaseKey,
    entities::{
        E2eiAcmeCA, E2eiCrl, E2eiEnrollment, E2eiIntermediateCert, E2eiRefreshToken, Entity as _, EntityBase as _,
        MlsCredential, MlsEncryptionKeyPair, MlsEpochEncryptionKeyPair, MlsHpkePrivateKey, MlsKeyPackage,
        MlsPendingMessage, MlsPskBundle, MlsSignatureKeyPair, PersistedMlsGroup, PersistedMlsPendingGroup,
        ProteusIdentity, ProteusPrekey, ProteusSession,
    },
};

macro_rules! rekey_entities {
    ($db: ident, $old_cipher: ident, $new_cipher: ident, [$($entity:ty),*]) => {
        let serializer = serde_wasm_bindgen::Serializer::json_compatible();
        let transaction = $db.transaction(&$db.store_names(), TransactionMode::ReadWrite)?;

        $(
            let store = transaction.object_store(<$entity>::COLLECTION_NAME)?;
            let js_values = store.get_all(None, None)?.await?;
            for js_value in js_values {
                let mut entity: $entity = serde_wasm_bindgen::from_value(js_value)?;
                entity.decrypt(&$old_cipher)?;
                let key = entity.id()?;
                entity.encrypt(&$new_cipher)?;
                let js_value = entity.serialize(&serializer)?;
                store.put(&js_value, Some(&key))?.await?;
            }
        )*

        let result = transaction.await?;
        if !result.is_committed() {
            return Err(CryptoKeystoreError::MigrationFailed);
        }
    }
}

pub(crate) async fn migrate_db_key_type_to_bytes(
    name: &str,
    old_key: &str,
    new_key: &DatabaseKey,
) -> CryptoKeystoreResult<()> {
    let old_cipher = aes_gcm::Aes256Gcm::new(&sha2::Sha256::digest(old_key));
    let new_cipher = aes_gcm::Aes256Gcm::new(new_key.as_ref().into());

    let db = pre_v4::open_and_migrate(name, old_key).await?;

    // The database could have been originally at version 3, or some older version,
    // but after migration, it has to be at 3.
    let version = db.version()?;
    assert!(version == DB_VERSION_3);

    rekey_entities!(
        db,
        old_cipher,
        new_cipher,
        [
            MlsCredential,
            MlsSignatureKeyPair,
            MlsHpkePrivateKey,
            MlsEncryptionKeyPair,
            MlsEpochEncryptionKeyPair,
            MlsPskBundle,
            MlsKeyPackage,
            PersistedMlsGroup,
            PersistedMlsPendingGroup,
            MlsPendingMessage,
            E2eiEnrollment,
            E2eiRefreshToken,
            E2eiAcmeCA,
            E2eiIntermediateCert,
            E2eiCrl,
            ProteusPrekey,
            ProteusIdentity,
            ProteusSession
        ]
    );

    db.close();

    // Update the database version to 4.
    let db = Factory::new()?.open(name, Some(DB_VERSION_4))?.await?;
    db.close();

    Ok(())
}
