use aes_gcm::KeyInit as _;
use idb::{Factory, TransactionMode};
use sha2::Digest as _;

use super::{DB_VERSION_3, DB_VERSION_4, pre_v04};
use crate::{
    CryptoKeystoreError, CryptoKeystoreResult, DatabaseKey,
    connection::idb_migration::legacy::{
        connection::wasm::rekey::rekey_entities,
        entities::mls::{
            e2ei_acme_ca::E2eiAcmeCA, e2ei_crl::E2eiCrl, e2ei_intermediate_cert::E2eiIntermediateCert,
            stored_keypackage::StoredKeypackage,
        },
    },
    entities::{
        MlsPendingMessage, PersistedMlsPendingGroup, ProteusIdentity, ProteusPrekey, ProteusSession,
        StoredEncryptionKeyPair, StoredHpkePrivateKey, StoredPskBundle,
    },
    migrations::{LegacyPersistedMlsGroup, StoredSignatureKeypair, V5Credential, V33StoredEpochEncryptionKeypair},
};

pub(crate) async fn migrate_db_key_type_to_bytes(
    name: &str,
    old_key: &str,
    new_key: &DatabaseKey,
) -> CryptoKeystoreResult<()> {
    let old_cipher = aes_gcm::Aes256Gcm::new(&sha2::Sha256::digest(old_key));
    let new_cipher = aes_gcm::Aes256Gcm::new(AsRef::<[u8; _]>::as_ref(new_key).into());

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
            V33StoredEpochEncryptionKeypair,
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
