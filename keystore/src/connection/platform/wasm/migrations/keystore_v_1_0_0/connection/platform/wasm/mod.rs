use crate::connection::platform::wasm::migrations::db_version_number;
use crate::keystore_v_1_0_0::{
    CryptoKeystoreResult,
    connection::{DatabaseConnection, DatabaseConnectionRequirements},
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
        let version = db_version_number(0);

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
                    .add_index(Index::new("signature_scheme", "signature_scheme"))
                    .add_index(Index::new("signature_pk", "pk")),
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
