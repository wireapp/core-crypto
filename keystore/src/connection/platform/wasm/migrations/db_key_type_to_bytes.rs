use aes_gcm::KeyInit as _;
use idb::{Factory, TransactionMode};
use sha2::Digest as _;

use super::{DB_VERSION_3, DB_VERSION_4, pre_v04};
use crate::{
    CryptoKeystoreError, CryptoKeystoreResult, DatabaseKey,
    connection::platform::wasm::rekey::rekey_entities,
    entities::{
        E2eiAcmeCA, E2eiCrl, E2eiIntermediateCert, E2eiRefreshToken, MlsPendingMessage, PersistedMlsGroup,
        PersistedMlsPendingGroup, ProteusIdentity, ProteusPrekey, ProteusSession, StoredE2eiEnrollment,
        StoredEncryptionKeyPair, StoredEpochEncryptionKeypair, StoredHpkePrivateKey, StoredKeypackage, StoredPskBundle,
    },
    migrations::{StoredSignatureKeypair, V5Credential},
};

pub(crate) async fn migrate_db_key_type_to_bytes(
    name: &str,
    old_key: &str,
    new_key: &DatabaseKey,
) -> CryptoKeystoreResult<()> {
    let old_cipher = aes_gcm::Aes256Gcm::new(&sha2::Sha256::digest(old_key));
    let new_cipher = aes_gcm::Aes256Gcm::new(new_key.as_ref().into());

    let db = pre_v04::open_and_migrate(name).await?;

    // The database could have been originally at version 3, or some older version,
    // but after migration, it has to be at 3.
    let version = db.version()?;
    assert!(version == DB_VERSION_3);

    rekey_entities!(
        db,
        old_cipher,
        new_cipher,
        [
            V5Credential,
            StoredSignatureKeypair,
            StoredHpkePrivateKey,
            StoredEncryptionKeyPair,
            StoredEpochEncryptionKeypair,
            StoredPskBundle,
            StoredKeypackage,
            PersistedMlsGroup,
            PersistedMlsPendingGroup,
            MlsPendingMessage,
            StoredE2eiEnrollment,
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
