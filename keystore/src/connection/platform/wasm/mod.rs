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

use crate::{
    connection::{DatabaseConnection, DatabaseConnectionRequirements},
    CryptoKeystoreResult,
};
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

impl DatabaseConnectionRequirements for WasmConnection {}

#[cfg_attr(target_family = "wasm", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_family = "wasm"), async_trait::async_trait)]
impl DatabaseConnection for WasmConnection {
    async fn open(name: &str, key: &str) -> CryptoKeystoreResult<Self> {
        let name = name.to_string();
        // ? Maybe find a cleaner way to define the schema

        let version_major = env!("CARGO_PKG_VERSION_MAJOR").parse::<u32>().unwrap_or_default();
        let version_minor = env!("CARGO_PKG_VERSION_MINOR").parse::<u32>().unwrap_or_default();
        let version_patch = env!("CARGO_PKG_VERSION_PATCH").parse::<u32>().unwrap_or_default();

        // Watch out: we'll have issues after major version 4294.xx.xx lol
        let version = version_major * 1_000_000 + version_minor * 1_000 + version_patch;

        let rexie_builder = rexie::Rexie::builder(&name)
            .version(version)
            .add_object_store(
                ObjectStore::new("mls_credentials")
                    .auto_increment(false)
                    .add_index(Index::new("id", "id"))
                    .add_index(Index::new("credential", "credential").unique(true)),
            )
            .add_object_store(
                ObjectStore::new("mls_signature_keypairs")
                    .auto_increment(false)
                    .add_index(Index::new("mls_id", "mls_id"))
                    .add_index(Index::new("signature_scheme", "signature_scheme"))
                    .add_index(Index::new("pk", "pk").unique(true)),
            )
            .add_object_store(
                ObjectStore::new("mls_hpke_private_keys")
                    .auto_increment(false)
                    .add_index(Index::new("pk", "pk").unique(true)),
            )
            .add_object_store(
                ObjectStore::new("mls_encryption_keypairs")
                    .auto_increment(false)
                    .add_index(Index::new("pk", "pk").unique(true)),
            )
            .add_object_store(
                ObjectStore::new("mls_epoch_encryption_keypairs")
                    .auto_increment(false)
                    .add_index(Index::new("id", "id").unique(true)),
            )
            .add_object_store(
                ObjectStore::new("mls_psk_bundles")
                    .auto_increment(false)
                    .add_index(Index::new("psk_id", "psk_id").unique(true)),
            )
            .add_object_store(
                ObjectStore::new("mls_keypackages")
                    .auto_increment(false)
                    .add_index(Index::new("keypackage_ref", "keypackage_ref").unique(true)),
            )
            .add_object_store(
                ObjectStore::new("mls_groups")
                    .auto_increment(false)
                    .add_index(Index::new("id", "id").unique(true)),
            )
            .add_object_store(
                ObjectStore::new("mls_pending_groups")
                    .auto_increment(false)
                    .add_index(Index::new("id", "id").unique(true)),
            )
            .add_object_store(
                ObjectStore::new("mls_pending_messages")
                    .auto_increment(false)
                    .add_index(Index::new("id", "id")),
            )
            .add_object_store(
                ObjectStore::new("e2ei_enrollment")
                    .auto_increment(false)
                    .add_index(Index::new("id", "id").unique(true)),
            )
            .add_object_store(
                ObjectStore::new("e2ei_refresh_token")
                    .auto_increment(false)
                    .add_index(Index::new("id", "id").unique(true)),
            )
            .add_object_store(
                ObjectStore::new("e2ei_acme_ca")
                    .auto_increment(false)
                    .add_index(Index::new("id", "id").unique(true)),
            )
            .add_object_store(
                ObjectStore::new("e2ei_intermediate_certs")
                    .auto_increment(false)
                    .add_index(Index::new("ski_aki_pair", "ski_aki_pair").unique(true)),
            )
            .add_object_store(
                ObjectStore::new("e2ei_crls")
                    .auto_increment(false)
                    .add_index(Index::new("distribution_point", "distribution_point").unique(true)),
            )
            .add_object_store(
                ObjectStore::new("proteus_prekeys")
                    .auto_increment(false)
                    .add_index(Index::new("id", "id").unique(true)),
            )
            .add_object_store(
                ObjectStore::new("proteus_identities")
                    .auto_increment(false)
                    .add_index(Index::new("pk", "pk").unique(true)),
            )
            .add_object_store(
                ObjectStore::new("proteus_sessions")
                    .auto_increment(false)
                    .add_index(Index::new("id", "id").unique(true)),
            );

        #[cfg(feature = "idb-regression-test")]
        let rexie_builder = rexie_builder.add_object_store(ObjectStore::new("regression_check").auto_increment(false));

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
