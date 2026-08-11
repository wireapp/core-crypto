use aes_gcm::KeyInit as _;
use idb::Factory;
use idb::TransactionMode;
use sha2::Digest as _;

use super::DB_VERSION_3;
use super::DB_VERSION_4;
use super::pre_v04;
use crate::CryptoKeystoreError;
use crate::CryptoKeystoreResult;
use crate::DatabaseKey;
use crate::connection::idb_migration::legacy::connection::wasm::rekey::rekey_entities;
use crate::connection::idb_migration::legacy::entities::mls::e2ei_acme_ca::E2eiAcmeCA;
use crate::connection::idb_migration::legacy::entities::mls::e2ei_crl::E2eiCrl;
use crate::connection::idb_migration::legacy::entities::mls::e2ei_intermediate_cert::E2eiIntermediateCert;
use crate::connection::idb_migration::legacy::entities::mls::stored_keypackage::StoredKeypackage;
use crate::entities::MlsPendingMessage;
use crate::entities::PersistedMlsPendingGroup;
use crate::entities::ProteusIdentity;
use crate::entities::ProteusPrekey;
use crate::entities::ProteusSession;
use crate::entities::StoredEncryptionKeyPair;
use crate::entities::StoredEpochEncryptionKeypair;
use crate::entities::StoredHpkePrivateKey;
use crate::entities::StoredPskBundle;
use crate::migrations::LegacyPersistedMlsGroup;
use crate::migrations::StoredSignatureKeypair;
use crate::migrations::V5Credential;

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
    if version != DB_VERSION_3 {
        db.close();
        return Err(CryptoKeystoreError::MigrationFailed(
            "key type migration from string to bytes can and should only be done once, on legacy \
             IndexedDB databases corresponding to a core crypto version <= 5."
                .to_string(),
        ));
    }

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
            LegacyPersistedMlsGroup,
            PersistedMlsPendingGroup,
            MlsPendingMessage,
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
