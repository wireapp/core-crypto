use aes_gcm::KeyInit as _;
use idb::{Factory, TransactionMode};

use crate::{
    CryptoKeystoreError, CryptoKeystoreResult,
    connection::{
        DatabaseConnection, DatabaseConnectionRequirements, DatabaseKey, platform::wasm::migrations::open_and_migrate,
    },
    entities::{
        E2eiAcmeCA, E2eiCrl, E2eiIntermediateCert, MlsPendingMessage, PersistedMlsGroup, PersistedMlsPendingGroup,
        ProteusIdentity, ProteusPrekey, ProteusSession, StoredCredential, StoredE2eiEnrollment,
        StoredEncryptionKeyPair, StoredEpochEncryptionKeypair, StoredHpkePrivateKey, StoredKeypackage, StoredPskBundle,
    },
};

mod migrations;
mod rekey;
pub mod storage;

use self::storage::{WasmEncryptedStorage, WasmStorageTransaction, WasmStorageWrapper};

#[derive(Debug)]
pub struct WasmConnection {
    name: Option<String>,
    conn: WasmEncryptedStorage,
}

impl WasmConnection {
    pub fn name(&self) -> &Option<String> {
        &self.name
    }

    pub fn storage(&self) -> &WasmEncryptedStorage {
        &self.conn
    }

    pub fn storage_mut(&mut self) -> &mut WasmEncryptedStorage {
        &mut self.conn
    }

    // for compatibility with the uniffi version
    pub async fn conn(&self) -> TransactionCreator<'_> {
        TransactionCreator { conn: &self.conn }
    }

    pub async fn migrate_db_key_type_to_bytes(
        name: &str,
        old_key: &str,
        new_key: &DatabaseKey,
    ) -> CryptoKeystoreResult<()> {
        migrations::migrate_db_key_type_to_bytes(name, old_key, new_key).await
    }

    pub async fn close(self) -> CryptoKeystoreResult<()> {
        self.conn.close()?;

        Ok(())
    }

    /// Only for use during migrations.
    pub(crate) fn from_inner(inner: WasmEncryptedStorage) -> Self {
        Self {
            name: None,
            conn: inner,
        }
    }
}

impl DatabaseConnectionRequirements for WasmConnection {}

#[cfg_attr(target_family = "wasm", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_family = "wasm"), async_trait::async_trait)]
impl<'a> DatabaseConnection<'a> for WasmConnection {
    type Connection = &'a WasmEncryptedStorage;

    async fn open(name: &str, key: &DatabaseKey) -> CryptoKeystoreResult<Self> {
        let name = name.to_string();
        // ? Maybe find a cleaner way to define the schema

        let idb = open_and_migrate(&name, key).await?;

        let storage = WasmStorageWrapper::Persistent(idb);

        let conn = WasmEncryptedStorage::new(key, storage);

        Ok(Self { name: Some(name), conn })
    }

    async fn open_in_memory(key: &DatabaseKey) -> CryptoKeystoreResult<Self> {
        let storage = WasmStorageWrapper::InMemory(Default::default());
        let conn = WasmEncryptedStorage::new(key, storage);
        Ok(Self { name: None, conn })
    }

    async fn update_key(&mut self, new_key: &DatabaseKey) -> CryptoKeystoreResult<()> {
        match self.conn.storage {
            WasmStorageWrapper::Persistent(ref mut db) => {
                let old_cipher = self.conn.cipher.clone();
                let new_cipher = aes_gcm::Aes256Gcm::new(new_key.as_ref().into());

                rekey::rekey_entities_new!(
                    db,
                    old_cipher,
                    new_cipher,
                    [
                        StoredCredential,
                        StoredHpkePrivateKey,
                        StoredEncryptionKeyPair,
                        StoredEpochEncryptionKeypair,
                        StoredPskBundle,
                        StoredKeypackage,
                        PersistedMlsGroup,
                        PersistedMlsPendingGroup,
                        MlsPendingMessage,
                        StoredE2eiEnrollment,
                        E2eiAcmeCA,
                        E2eiIntermediateCert,
                        E2eiCrl,
                        ProteusPrekey,
                        ProteusIdentity,
                        ProteusSession
                    ]
                );
            }
            WasmStorageWrapper::InMemory(_) => return Err(CryptoKeystoreError::NotImplemented),
        }

        Ok(())
    }

    async fn wipe(self) -> CryptoKeystoreResult<()> {
        if self.conn.is_persistent() {
            let factory = Factory::new()?;
            factory
                .delete(&self.name.expect("name is always set for a persistent connection"))?
                .await?;
        }

        Ok(())
    }
}

/// A connection reference which can create a new transaction.
///
/// This is kind of weird but it's necessary for interop with the generic/uniffi side.
pub struct TransactionCreator<'a> {
    conn: &'a WasmEncryptedStorage,
}

impl TransactionCreator<'_> {
    pub async fn new_transaction(
        &mut self,
        tables: &[impl AsRef<str>],
    ) -> CryptoKeystoreResult<WasmStorageTransaction<'_>> {
        match &self.conn.storage {
            WasmStorageWrapper::Persistent(db) => Ok(WasmStorageTransaction::Persistent {
                tx: db.transaction(tables, TransactionMode::ReadWrite)?,
                cipher: &self.conn.cipher,
            }),
            WasmStorageWrapper::InMemory(db) => Ok(WasmStorageTransaction::InMemory {
                db: db.clone(),
                cipher: &self.conn.cipher,
            }),
        }
    }
}
