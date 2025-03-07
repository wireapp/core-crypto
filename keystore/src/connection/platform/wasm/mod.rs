// Wire
// Copyright (C) 2022 Wire Swiss GmbH

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with this program. If not, see http://www.gnu.org/licenses/.

use crate::connection::platform::wasm::migrations::open_and_migrate;
use crate::{
    CryptoKeystoreResult,
    connection::{DatabaseConnection, DatabaseConnectionRequirements},
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

    async fn open(name: &str, key: &str) -> CryptoKeystoreResult<Self> {
        let name = name.to_string();
        // ? Maybe find a cleaner way to define the schema

        let idb = open_and_migrate(&name, key).await?;

        let storage = WasmStorageWrapper::Persistent(idb);

        let conn = WasmEncryptedStorage::new(key, storage);

        Ok(Self { name, conn })
    }

    async fn open_in_memory(name: &str, key: &str) -> CryptoKeystoreResult<Self> {
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
