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

use crate::connection::platform::wasm::migrations::migrate;
use crate::{
    connection::{DatabaseConnection, DatabaseConnectionRequirements},
    CryptoKeystoreResult,
};
use idb::Factory;

mod migrations;
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

impl DatabaseConnectionRequirements for WasmConnection {}

fn determine_pre_version(pre_str: &str) -> u32 {
    let mut pre_parts = pre_str.split('+');
    // We ignore the build number for simplicity's sake and we don't really use it either
    // So we just pick what's before the build number
    let Some(pre_version) = pre_parts.next() else {
        return 0;
    };

    // <pre-release identifier> "." <dot-separated pre-release identifiers>
    let mut pre_version_parts = pre_version.split('.');

    // grab the pre-version identifier (i.e. alpha, beta, pre, rc, etc)
    let Some(pre_identifier) = pre_version_parts.next() else {
        return 0;
    };

    // grab the pre-version build identifier i.e. rc.24, here we extract and parse the "24"
    let pre_identifier_version = pre_version_parts
        .next()
        .and_then(|v| v.parse::<u32>().ok())
        .unwrap_or_default();

    let base_version = match pre_identifier {
        "alpha" => 200,
        "beta" => 400,
        "pre" => 600,
        "rc" => 800,
        _ => 0,
    };

    base_version + pre_identifier_version
}

const fn version_number(version_major: u32, version_minor: u32, version_patch: u32, version_pre: u32) -> u32 {
    version_major * 10_000_000 + version_minor * 100_000 + version_patch * 1_000 + version_pre
}

#[cfg_attr(target_family = "wasm", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_family = "wasm"), async_trait::async_trait)]
impl DatabaseConnection for WasmConnection {
    async fn open(name: &str, key: &str) -> CryptoKeystoreResult<Self> {
        let name = name.to_string();
        // ? Maybe find a cleaner way to define the schema

        let version_major = env!("CARGO_PKG_VERSION_MAJOR").parse::<u32>().unwrap_or_default();
        let version_minor = env!("CARGO_PKG_VERSION_MINOR").parse::<u32>().unwrap_or_default();
        let version_patch = env!("CARGO_PKG_VERSION_PATCH").parse::<u32>().unwrap_or_default();
        let version_pre: u32 = determine_pre_version(env!("CARGO_PKG_VERSION_PRE"));

        // ? Watch out, version limits, do NOT exceed those before patching:
        // - major: breaks after version 429
        // - minor: breaks after version 99
        // - patch: breaks after version 99
        // - prerelease: breaks after rc.99
        // - build: breaks after r9
        let version = version_number(version_major, version_minor, version_patch, version_pre);

        let factory = Factory::new()?;

        let open_existing = factory.open(&name, None)?;
        let existing_db = open_existing.await?;
        let mut migrated_version = existing_db.version()?;

        let idb = if migrated_version == version {
            // Migration is not needed, just return existing db
            existing_db
        } else {
            // Migration is needed
            existing_db.close();

            while migrated_version < version {
                migrated_version = migrate(migrated_version, version, &name, key).await?;
            }

            let open_request = factory.open(&name, Some(version))?;
            open_request.await?
        };

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
