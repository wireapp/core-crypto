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

use crate::{connection::DatabaseConnection, CryptoKeystoreResult};
use rexie::{Index, ObjectStore};

pub mod storage;
use self::storage::{WasmEncryptedStorage, WasmStorageWrapper};

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
}

#[async_trait::async_trait(?Send)]
impl DatabaseConnection for WasmConnection {
    async fn open(name: &str, key: &str) -> CryptoKeystoreResult<Self> {
        let name = name.to_string();
        // ? Maybe find a cleaner way to define the schema
        let rexie_builder = rexie::Rexie::builder(&name)
            .version(1)
            .add_object_store(ObjectStore::new("mls_keys").auto_increment(false))
            .add_object_store(
                ObjectStore::new("mls_identities")
                    .auto_increment(false)
                    .add_index(Index::new("signature", "signature").unique(true)),
            )
            .add_object_store(ObjectStore::new("proteus_prekeys").auto_increment(false))
            .add_object_store(ObjectStore::new("mls_groups").auto_increment(false))
            .add_object_store(ObjectStore::new("mls_pending_groups").auto_increment(false));

        let rexie = rexie_builder.build().await?;

        let storage = WasmStorageWrapper::Persistent(rexie);
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
            let _ = rexie::Rexie::builder(&self.name).delete().await?;
        }

        Ok(())
    }
}
