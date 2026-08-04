use idb::{
    KeyPath,
    builder::{DatabaseBuilder, IndexBuilder, ObjectStoreBuilder},
};

use super::DB_VERSION_0;
use crate::{
    connection::idb_migration::legacy::{entities::mls::e2ei_acme_ca::E2eiAcmeCA, traits::EntityBase as _},
    entities::{
        E2eiCrl, E2eiIntermediateCert, MlsPendingMessage, PersistedMlsPendingGroup, ProteusIdentity, ProteusPrekey,
        ProteusSession, StoredEncryptionKeyPair, StoredEpochEncryptionKeypair, StoredHpkePrivateKey, StoredPskBundle,
    },
    migrations::{LegacyPersistedMlsGroup, LegacyStoredKeypackage, StoredSignatureKeypair, V5Credential},
};

pub(super) fn get_builder(name: &str) -> DatabaseBuilder {
    DatabaseBuilder::new(name)
        .version(DB_VERSION_0)
        .add_object_store(
            ObjectStoreBuilder::new(V5Credential::TABLE_NAME)
                .auto_increment(false)
                .add_index(IndexBuilder::new("id".into(), KeyPath::new_single("id")))
                .add_index(IndexBuilder::new("credential".into(), KeyPath::new_single("credential")).unique(true)),
        )
        .add_object_store(
            ObjectStoreBuilder::new(StoredSignatureKeypair::TABLE_NAME)
                .auto_increment(false)
                .add_index(IndexBuilder::new(
                    "signature_scheme".into(),
                    KeyPath::new_single("signature_scheme"),
                ))
                .add_index(IndexBuilder::new("signature_pk".into(), KeyPath::new_single("pk"))),
        )
        .add_object_store(
            ObjectStoreBuilder::new(StoredHpkePrivateKey::TABLE_NAME)
                .auto_increment(false)
                .add_index(IndexBuilder::new("pk".into(), KeyPath::new_single("pk")).unique(true)),
        )
        .add_object_store(
            ObjectStoreBuilder::new(StoredEncryptionKeyPair::TABLE_NAME)
                .auto_increment(false)
                .add_index(IndexBuilder::new("pk".into(), KeyPath::new_single("pk")).unique(true)),
        )
        .add_object_store(
            ObjectStoreBuilder::new(StoredEpochEncryptionKeypair::TABLE_NAME)
                .auto_increment(false)
                .add_index(IndexBuilder::new("id".into(), KeyPath::new_single("id")).unique(true)),
        )
        .add_object_store(
            ObjectStoreBuilder::new(StoredPskBundle::TABLE_NAME)
                .auto_increment(false)
                .add_index(IndexBuilder::new("psk_id".into(), KeyPath::new_single("psk_id")).unique(true)),
        )
        .add_object_store(
            ObjectStoreBuilder::new(LegacyStoredKeypackage::TABLE_NAME)
                .auto_increment(false)
                .add_index(
                    IndexBuilder::new("keypackage_ref".into(), KeyPath::new_single("keypackage_ref")).unique(true),
                ),
        )
        .add_object_store(
            ObjectStoreBuilder::new(LegacyPersistedMlsGroup::TABLE_NAME)
                .auto_increment(false)
                .add_index(IndexBuilder::new("id".into(), KeyPath::new_single("id")).unique(true)),
        )
        .add_object_store(
            ObjectStoreBuilder::new(PersistedMlsPendingGroup::TABLE_NAME)
                .auto_increment(false)
                .add_index(IndexBuilder::new("id".into(), KeyPath::new_single("id")).unique(true)),
        )
        .add_object_store(
            ObjectStoreBuilder::new(MlsPendingMessage::TABLE_NAME)
                .auto_increment(false)
                .add_index(IndexBuilder::new("id".into(), KeyPath::new_single("id"))),
        )
        .add_object_store(
            ObjectStoreBuilder::new(E2eiAcmeCA::TABLE_NAME)
                .auto_increment(false)
                .add_index(IndexBuilder::new("id".into(), KeyPath::new_single("id")).unique(true)),
        )
        .add_object_store(
            ObjectStoreBuilder::new(E2eiIntermediateCert::TABLE_NAME)
                .auto_increment(false)
                .add_index(IndexBuilder::new("ski_aki_pair".into(), KeyPath::new_single("ski_aki_pair")).unique(true)),
        )
        .add_object_store(
            ObjectStoreBuilder::new(E2eiCrl::TABLE_NAME)
                .auto_increment(false)
                .add_index(
                    IndexBuilder::new("distribution_point".into(), KeyPath::new_single("distribution_point"))
                        .unique(true),
                ),
        )
        .add_object_store(
            ObjectStoreBuilder::new(ProteusPrekey::TABLE_NAME)
                .auto_increment(false)
                .add_index(IndexBuilder::new("id".into(), KeyPath::new_single("id")).unique(true)),
        )
        .add_object_store(
            ObjectStoreBuilder::new(ProteusIdentity::TABLE_NAME)
                .auto_increment(false)
                .add_index(IndexBuilder::new("pk".into(), KeyPath::new_single("pk")).unique(true)),
        )
        .add_object_store(
            ObjectStoreBuilder::new(ProteusSession::TABLE_NAME)
                .auto_increment(false)
                .add_index(IndexBuilder::new("id".into(), KeyPath::new_single("id")).unique(true)),
        )
}
