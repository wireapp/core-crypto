use idb::{
    KeyPath,
    builder::{IndexBuilder, ObjectStoreBuilder},
};

use super::{DB_VERSION_0, Metabuilder};
use crate::entities::{
    E2eiAcmeCA, E2eiCrl, E2eiIntermediateCert, E2eiRefreshToken, EntityBase as _, MlsPendingMessage, PersistedMlsGroup,
    PersistedMlsPendingGroup, ProteusIdentity, ProteusPrekey, ProteusSession, StoredCredential, StoredE2eiEnrollment,
    StoredEncryptionKeyPair, StoredEpochEncryptionKeypair, StoredHpkePrivateKey, StoredKeypackage, StoredPskBundle,
    StoredSignatureKeypair,
};

pub(super) fn get_builder(name: &str) -> Metabuilder {
    let idb_builder = Metabuilder::new(name)
        .version(DB_VERSION_0)
        .add_object_store(
            ObjectStoreBuilder::new(StoredCredential::COLLECTION_NAME)
                .auto_increment(false)
                .add_index(IndexBuilder::new("id".into(), KeyPath::new_single("id")))
                .add_index(IndexBuilder::new("credential".into(), KeyPath::new_single("credential")).unique(true)),
        )
        .add_object_store(
            ObjectStoreBuilder::new(StoredSignatureKeypair::COLLECTION_NAME)
                .auto_increment(false)
                .add_index(IndexBuilder::new(
                    "signature_scheme".into(),
                    KeyPath::new_single("signature_scheme"),
                ))
                .add_index(IndexBuilder::new("signature_pk".into(), KeyPath::new_single("pk"))),
        )
        .add_object_store(
            ObjectStoreBuilder::new(StoredHpkePrivateKey::COLLECTION_NAME)
                .auto_increment(false)
                .add_index(IndexBuilder::new("pk".into(), KeyPath::new_single("pk")).unique(true)),
        )
        .add_object_store(
            ObjectStoreBuilder::new(StoredEncryptionKeyPair::COLLECTION_NAME)
                .auto_increment(false)
                .add_index(IndexBuilder::new("pk".into(), KeyPath::new_single("pk")).unique(true)),
        )
        .add_object_store(
            ObjectStoreBuilder::new(StoredEpochEncryptionKeypair::COLLECTION_NAME)
                .auto_increment(false)
                .add_index(IndexBuilder::new("id".into(), KeyPath::new_single("id")).unique(true)),
        )
        .add_object_store(
            ObjectStoreBuilder::new(StoredPskBundle::COLLECTION_NAME)
                .auto_increment(false)
                .add_index(IndexBuilder::new("psk_id".into(), KeyPath::new_single("psk_id")).unique(true)),
        )
        .add_object_store(
            ObjectStoreBuilder::new(StoredKeypackage::COLLECTION_NAME)
                .auto_increment(false)
                .add_index(
                    IndexBuilder::new("keypackage_ref".into(), KeyPath::new_single("keypackage_ref")).unique(true),
                ),
        )
        .add_object_store(
            ObjectStoreBuilder::new(PersistedMlsGroup::COLLECTION_NAME)
                .auto_increment(false)
                .add_index(IndexBuilder::new("id".into(), KeyPath::new_single("id")).unique(true)),
        )
        .add_object_store(
            ObjectStoreBuilder::new(PersistedMlsPendingGroup::COLLECTION_NAME)
                .auto_increment(false)
                .add_index(IndexBuilder::new("id".into(), KeyPath::new_single("id")).unique(true)),
        )
        .add_object_store(
            ObjectStoreBuilder::new(MlsPendingMessage::COLLECTION_NAME)
                .auto_increment(false)
                .add_index(IndexBuilder::new("id".into(), KeyPath::new_single("id"))),
        )
        .add_object_store(
            ObjectStoreBuilder::new(StoredE2eiEnrollment::COLLECTION_NAME)
                .auto_increment(false)
                .add_index(IndexBuilder::new("id".into(), KeyPath::new_single("id")).unique(true)),
        )
        .add_object_store(
            ObjectStoreBuilder::new(E2eiRefreshToken::COLLECTION_NAME)
                .auto_increment(false)
                .add_index(IndexBuilder::new("id".into(), KeyPath::new_single("id")).unique(true)),
        )
        .add_object_store(
            ObjectStoreBuilder::new(E2eiAcmeCA::COLLECTION_NAME)
                .auto_increment(false)
                .add_index(IndexBuilder::new("id".into(), KeyPath::new_single("id")).unique(true)),
        )
        .add_object_store(
            ObjectStoreBuilder::new(E2eiIntermediateCert::COLLECTION_NAME)
                .auto_increment(false)
                .add_index(IndexBuilder::new("ski_aki_pair".into(), KeyPath::new_single("ski_aki_pair")).unique(true)),
        )
        .add_object_store(
            ObjectStoreBuilder::new(E2eiCrl::COLLECTION_NAME)
                .auto_increment(false)
                .add_index(
                    IndexBuilder::new("distribution_point".into(), KeyPath::new_single("distribution_point"))
                        .unique(true),
                ),
        )
        .add_object_store(
            ObjectStoreBuilder::new(ProteusPrekey::COLLECTION_NAME)
                .auto_increment(false)
                .add_index(IndexBuilder::new("id".into(), KeyPath::new_single("id")).unique(true)),
        )
        .add_object_store(
            ObjectStoreBuilder::new(ProteusIdentity::COLLECTION_NAME)
                .auto_increment(false)
                .add_index(IndexBuilder::new("pk".into(), KeyPath::new_single("pk")).unique(true)),
        )
        .add_object_store(
            ObjectStoreBuilder::new(ProteusSession::COLLECTION_NAME)
                .auto_increment(false)
                .add_index(IndexBuilder::new("id".into(), KeyPath::new_single("id")).unique(true)),
        );
    #[cfg(feature = "idb-regression-test")]
    let idb_builder = idb_builder.add_object_store(ObjectStoreBuilder::new("regression_check").auto_increment(false));
    idb_builder
}
