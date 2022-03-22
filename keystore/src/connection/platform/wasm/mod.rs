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
use rexie::ObjectStore;
use wasm_bindgen_futures::spawn_local;

pub mod storage;
use self::storage::{WasmEncryptedStorage, WasmStorageWrapper};

#[derive(Debug)]
pub struct WasmConnection {
    name: String,
    conn: WasmEncryptedStorage,
}

// FIXME: Fix persitent storage's timeout
// FIXME: Enable the persistent storage in mls-provider

unsafe impl Send for WasmConnection {}
unsafe impl Sync for WasmConnection {}

impl WasmConnection {
    pub fn storage(&self) -> &WasmEncryptedStorage {
        &self.conn
    }

    pub fn storage_mut(&mut self) -> &mut WasmEncryptedStorage {
        &mut self.conn
    }
}

impl DatabaseConnection for WasmConnection {
    fn open<S: AsRef<str>, S2: AsRef<str>>(name: S, key: S2) -> CryptoKeystoreResult<Self> {
        let name = name.as_ref().to_string();
        // ? Maybe find a cleaner way to define the schema
        let rexie_builder = rexie::Rexie::builder(&name)
            .version(1)
            .add_object_store(ObjectStore::new("mls_keys").key_path("id"))
            .add_object_store(ObjectStore::new("mls_identities").key_path("id"))
            .add_object_store(ObjectStore::new("proteus_prekeys").key_path("id"))
            .add_object_store(ObjectStore::new("mls_groups").key_path("id"));

        let storage = crate::syncify!(async move {
            CryptoKeystoreResult::Ok(
                rexie_builder
                    .build()
                    .await
                    .map(|rexie| WasmStorageWrapper::Persistent(rexie))?,
            )
        })?;

        let conn = WasmEncryptedStorage::new(key, storage);

        Ok(Self { name, conn })
    }

    fn open_in_memory<S: AsRef<str>, S2: AsRef<str>>(name: S, key: S2) -> CryptoKeystoreResult<Self> {
        let name = name.as_ref().to_string();
        let storage = WasmStorageWrapper::InMemory(Default::default());
        let conn = WasmEncryptedStorage::new(key, storage);
        Ok(Self { name, conn })
    }

    fn close(self) -> CryptoKeystoreResult<()> {
        self.conn.close()?;

        Ok(())
    }

    fn wipe(self) -> CryptoKeystoreResult<()> {
        let is_persistent = self.conn.is_persistent();
        self.conn.close()?;

        if is_persistent {
            spawn_local(async move {
                let _ = rexie::Rexie::builder(&self.name).delete().await;
            });
        }

        Ok(())
    }
}
