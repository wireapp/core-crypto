use crate::connection::platform::wasm::migrations::open_and_migrate;
use crate::{
    CryptoKeystoreResult,
    connection::{DatabaseConnection, DatabaseConnectionRequirements, DatabaseKey},
};
use idb::{Factory, TransactionMode};

mod migrations;
pub use migrations::keystore_v_1_0_0;
pub mod storage;

use self::storage::{WasmEncryptedStorage, WasmStorageTransaction, WasmStorageWrapper};

#[derive(Debug)]
pub struct WasmConnection {
    name: String,
    conn: WasmEncryptedStorage,
}

impl WasmConnection {
    pub fn storage(&self) -> &WasmEncryptedStorage {
        &self.conn
    }

    pub fn storage_mut(&mut self) -> &mut WasmEncryptedStorage {
        &mut self.conn
    }

    // for compatibility with the uniffi version
    pub async fn conn(&self) -> TransactionCreator {
        TransactionCreator { conn: &self.conn }
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

        Ok(Self { name, conn })
    }

    async fn open_in_memory(name: &str, key: &DatabaseKey) -> CryptoKeystoreResult<Self> {
        let name = name.to_string();
        let storage = WasmStorageWrapper::InMemory(Default::default());
        let conn = WasmEncryptedStorage::new(key, storage);
        Ok(Self { name, conn })
    }

    async fn close(self) -> CryptoKeystoreResult<()> {
        self.conn.close()?;

        Ok(())
    }

    async fn wipe(self) -> CryptoKeystoreResult<()> {
        let is_persistent = self.conn.is_persistent();
        self.conn.close()?;

        if is_persistent {
            let factory = Factory::new()?;
            factory.delete(&self.name)?.await?;
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
