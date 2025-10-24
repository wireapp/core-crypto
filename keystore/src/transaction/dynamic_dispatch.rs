//! This module exists merely because the `Entity` trait is not object safe.
//! See <https://doc.rust-lang.org/reference/items/traits.html#object-safety.>.

#[cfg(target_family = "wasm")]
use crate::entities::E2eiRefreshToken;
#[cfg(feature = "proteus-keystore")]
use crate::entities::{ProteusIdentity, ProteusPrekey, ProteusSession};
use crate::{
    CryptoKeystoreError, CryptoKeystoreResult,
    connection::TransactionWrapper,
    entities::{
        ConsumerData, E2eiAcmeCA, E2eiCrl, E2eiIntermediateCert, EntityBase, EntityTransactionExt, MlsPendingMessage,
        PersistedMlsGroup, PersistedMlsPendingGroup, StoredBufferedCommit, StoredCredential, StoredE2eiEnrollment,
        StoredEncryptionKeyPair, StoredEpochEncryptionKeypair, StoredHpkePrivateKey, StoredKeypackage, StoredPskBundle,
        StoredSignatureKeypair, StringEntityId, UniqueEntity,
    },
};

#[derive(Debug)]
pub enum Entity {
    ConsumerData(ConsumerData),
    SignatureKeyPair(StoredSignatureKeypair),
    HpkePrivateKey(StoredHpkePrivateKey),
    StoredKeypackage(StoredKeypackage),
    PskBundle(StoredPskBundle),
    EncryptionKeyPair(StoredEncryptionKeyPair),
    StoredEpochEncryptionKeypair(StoredEpochEncryptionKeypair),
    StoredCredential(StoredCredential),
    StoredBufferedCommit(StoredBufferedCommit),
    PersistedMlsGroup(PersistedMlsGroup),
    PersistedMlsPendingGroup(PersistedMlsPendingGroup),
    MlsPendingMessage(MlsPendingMessage),
    StoredE2eiEnrollment(StoredE2eiEnrollment),
    #[cfg(target_family = "wasm")]
    E2eiRefreshToken(E2eiRefreshToken),
    E2eiAcmeCA(E2eiAcmeCA),
    E2eiIntermediateCert(E2eiIntermediateCert),
    E2eiCrl(E2eiCrl),
    #[cfg(feature = "proteus-keystore")]
    ProteusIdentity(ProteusIdentity),
    #[cfg(feature = "proteus-keystore")]
    ProteusPrekey(ProteusPrekey),
    #[cfg(feature = "proteus-keystore")]
    ProteusSession(ProteusSession),
}

#[derive(Debug, Clone, PartialEq)]
pub enum EntityId {
    SignatureKeyPair(Vec<u8>),
    HpkePrivateKey(Vec<u8>),
    KeyPackage(Vec<u8>),
    PskBundle(Vec<u8>),
    EncryptionKeyPair(Vec<u8>),
    EpochEncryptionKeyPair(Vec<u8>),
    StoredCredential(Vec<u8>),
    StoredBufferedCommit(Vec<u8>),
    PersistedMlsGroup(Vec<u8>),
    PersistedMlsPendingGroup(Vec<u8>),
    MlsPendingMessage(Vec<u8>),
    StoredE2eiEnrollment(Vec<u8>),
    #[cfg(target_family = "wasm")]
    E2eiRefreshToken(Vec<u8>),
    E2eiAcmeCA(Vec<u8>),
    E2eiIntermediateCert(Vec<u8>),
    E2eiCrl(Vec<u8>),
    #[cfg(feature = "proteus-keystore")]
    ProteusIdentity(Vec<u8>),
    #[cfg(feature = "proteus-keystore")]
    ProteusPrekey(Vec<u8>),
    #[cfg(feature = "proteus-keystore")]
    ProteusSession(Vec<u8>),
}

impl EntityId {
    fn as_id(&self) -> StringEntityId<'_> {
        match self {
            EntityId::SignatureKeyPair(vec) => vec.as_slice().into(),
            EntityId::HpkePrivateKey(vec) => vec.as_slice().into(),
            EntityId::KeyPackage(vec) => vec.as_slice().into(),
            EntityId::PskBundle(vec) => vec.as_slice().into(),
            EntityId::EncryptionKeyPair(vec) => vec.as_slice().into(),
            EntityId::EpochEncryptionKeyPair(vec) => vec.as_slice().into(),
            EntityId::StoredCredential(vec) => vec.as_slice().into(),
            EntityId::StoredBufferedCommit(vec) => vec.as_slice().into(),
            EntityId::PersistedMlsGroup(vec) => vec.as_slice().into(),
            EntityId::PersistedMlsPendingGroup(vec) => vec.as_slice().into(),
            EntityId::MlsPendingMessage(vec) => vec.as_slice().into(),
            EntityId::StoredE2eiEnrollment(vec) => vec.as_slice().into(),
            #[cfg(target_family = "wasm")]
            EntityId::E2eiRefreshToken(vec) => vec.as_slice().into(),
            EntityId::E2eiAcmeCA(vec) => vec.as_slice().into(),
            EntityId::E2eiIntermediateCert(vec) => vec.as_slice().into(),
            EntityId::E2eiCrl(vec) => vec.as_slice().into(),
            #[cfg(feature = "proteus-keystore")]
            EntityId::ProteusIdentity(vec) => vec.as_slice().into(),
            #[cfg(feature = "proteus-keystore")]
            EntityId::ProteusSession(id) => id.as_slice().into(),
            #[cfg(feature = "proteus-keystore")]
            EntityId::ProteusPrekey(vec) => vec.as_slice().into(),
        }
    }

    pub(crate) fn from_collection_name(entity_id: &'static str, id: &[u8]) -> CryptoKeystoreResult<Self> {
        match entity_id {
            StoredSignatureKeypair::COLLECTION_NAME => Ok(Self::SignatureKeyPair(id.into())),
            StoredHpkePrivateKey::COLLECTION_NAME => Ok(Self::HpkePrivateKey(id.into())),
            StoredKeypackage::COLLECTION_NAME => Ok(Self::KeyPackage(id.into())),
            StoredPskBundle::COLLECTION_NAME => Ok(Self::PskBundle(id.into())),
            StoredEncryptionKeyPair::COLLECTION_NAME => Ok(Self::EncryptionKeyPair(id.into())),
            StoredEpochEncryptionKeypair::COLLECTION_NAME => Ok(Self::EpochEncryptionKeyPair(id.into())),
            StoredBufferedCommit::COLLECTION_NAME => Ok(Self::StoredBufferedCommit(id.into())),
            PersistedMlsGroup::COLLECTION_NAME => Ok(Self::PersistedMlsGroup(id.into())),
            PersistedMlsPendingGroup::COLLECTION_NAME => Ok(Self::PersistedMlsPendingGroup(id.into())),
            StoredCredential::COLLECTION_NAME => Ok(Self::StoredCredential(id.into())),
            MlsPendingMessage::COLLECTION_NAME => Ok(Self::MlsPendingMessage(id.into())),
            StoredE2eiEnrollment::COLLECTION_NAME => Ok(Self::StoredE2eiEnrollment(id.into())),
            E2eiCrl::COLLECTION_NAME => Ok(Self::E2eiCrl(id.into())),
            E2eiAcmeCA::COLLECTION_NAME => Ok(Self::E2eiAcmeCA(id.into())),
            #[cfg(target_family = "wasm")]
            E2eiRefreshToken::COLLECTION_NAME => Ok(Self::E2eiRefreshToken(id.into())),
            E2eiIntermediateCert::COLLECTION_NAME => Ok(Self::E2eiIntermediateCert(id.into())),
            #[cfg(feature = "proteus-keystore")]
            ProteusIdentity::COLLECTION_NAME => Ok(Self::ProteusIdentity(id.into())),
            #[cfg(feature = "proteus-keystore")]
            ProteusPrekey::COLLECTION_NAME => Ok(Self::ProteusPrekey(id.into())),
            #[cfg(feature = "proteus-keystore")]
            ProteusSession::COLLECTION_NAME => Ok(Self::ProteusSession(id.into())),
            _ => Err(CryptoKeystoreError::NotImplemented),
        }
    }

    pub(crate) fn collection_name(&self) -> &'static str {
        match self {
            EntityId::SignatureKeyPair(_) => StoredSignatureKeypair::COLLECTION_NAME,
            EntityId::KeyPackage(_) => StoredKeypackage::COLLECTION_NAME,
            EntityId::PskBundle(_) => StoredPskBundle::COLLECTION_NAME,
            EntityId::EncryptionKeyPair(_) => StoredEncryptionKeyPair::COLLECTION_NAME,
            EntityId::EpochEncryptionKeyPair(_) => StoredEpochEncryptionKeypair::COLLECTION_NAME,
            EntityId::StoredCredential(_) => StoredCredential::COLLECTION_NAME,
            EntityId::StoredBufferedCommit(_) => StoredBufferedCommit::COLLECTION_NAME,
            EntityId::PersistedMlsGroup(_) => PersistedMlsGroup::COLLECTION_NAME,
            EntityId::PersistedMlsPendingGroup(_) => PersistedMlsPendingGroup::COLLECTION_NAME,
            EntityId::MlsPendingMessage(_) => MlsPendingMessage::COLLECTION_NAME,
            EntityId::StoredE2eiEnrollment(_) => StoredE2eiEnrollment::COLLECTION_NAME,
            #[cfg(target_family = "wasm")]
            EntityId::E2eiRefreshToken(_) => E2eiRefreshToken::COLLECTION_NAME,
            EntityId::E2eiAcmeCA(_) => E2eiAcmeCA::COLLECTION_NAME,
            EntityId::E2eiIntermediateCert(_) => E2eiIntermediateCert::COLLECTION_NAME,
            EntityId::E2eiCrl(_) => E2eiCrl::COLLECTION_NAME,
            #[cfg(feature = "proteus-keystore")]
            EntityId::ProteusIdentity(_) => ProteusIdentity::COLLECTION_NAME,
            #[cfg(feature = "proteus-keystore")]
            EntityId::ProteusPrekey(_) => ProteusPrekey::COLLECTION_NAME,
            #[cfg(feature = "proteus-keystore")]
            EntityId::ProteusSession(_) => ProteusSession::COLLECTION_NAME,
            EntityId::HpkePrivateKey(_) => StoredHpkePrivateKey::COLLECTION_NAME,
        }
    }
}

pub async fn execute_save(tx: &TransactionWrapper<'_>, entity: &Entity) -> CryptoKeystoreResult<()> {
    match entity {
        Entity::ConsumerData(consumer_data) => consumer_data.replace(tx).await,
        Entity::SignatureKeyPair(mls_signature_key_pair) => mls_signature_key_pair.save(tx).await,
        Entity::HpkePrivateKey(mls_hpke_private_key) => mls_hpke_private_key.save(tx).await,
        Entity::StoredKeypackage(mls_key_package) => mls_key_package.save(tx).await,
        Entity::PskBundle(mls_psk_bundle) => mls_psk_bundle.save(tx).await,
        Entity::EncryptionKeyPair(mls_encryption_key_pair) => mls_encryption_key_pair.save(tx).await,
        Entity::StoredEpochEncryptionKeypair(mls_epoch_encryption_key_pair) => {
            mls_epoch_encryption_key_pair.save(tx).await
        }
        Entity::StoredCredential(mls_credential) => mls_credential.save(tx).await,
        Entity::StoredBufferedCommit(mls_pending_commit) => mls_pending_commit.save(tx).await,
        Entity::PersistedMlsGroup(persisted_mls_group) => persisted_mls_group.save(tx).await,
        Entity::PersistedMlsPendingGroup(persisted_mls_pending_group) => persisted_mls_pending_group.save(tx).await,
        Entity::MlsPendingMessage(mls_pending_message) => mls_pending_message.save(tx).await,
        Entity::StoredE2eiEnrollment(e2ei_enrollment) => e2ei_enrollment.save(tx).await,
        #[cfg(target_family = "wasm")]
        Entity::E2eiRefreshToken(e2ei_refresh_token) => e2ei_refresh_token.replace(tx).await,
        Entity::E2eiAcmeCA(e2ei_acme_ca) => e2ei_acme_ca.replace(tx).await,
        Entity::E2eiIntermediateCert(e2ei_intermediate_cert) => e2ei_intermediate_cert.save(tx).await,
        Entity::E2eiCrl(e2ei_crl) => e2ei_crl.save(tx).await,
        #[cfg(feature = "proteus-keystore")]
        Entity::ProteusSession(record) => record.save(tx).await,
        #[cfg(feature = "proteus-keystore")]
        Entity::ProteusIdentity(record) => record.save(tx).await,
        #[cfg(feature = "proteus-keystore")]
        Entity::ProteusPrekey(record) => record.save(tx).await,
    }
}

pub async fn execute_delete(tx: &TransactionWrapper<'_>, entity_id: &EntityId) -> CryptoKeystoreResult<()> {
    match entity_id {
        id @ EntityId::SignatureKeyPair(_) => StoredSignatureKeypair::delete(tx, id.as_id()).await,
        id @ EntityId::HpkePrivateKey(_) => StoredHpkePrivateKey::delete(tx, id.as_id()).await,
        id @ EntityId::KeyPackage(_) => StoredKeypackage::delete(tx, id.as_id()).await,
        id @ EntityId::PskBundle(_) => StoredPskBundle::delete(tx, id.as_id()).await,
        id @ EntityId::EncryptionKeyPair(_) => StoredEncryptionKeyPair::delete(tx, id.as_id()).await,
        id @ EntityId::EpochEncryptionKeyPair(_) => StoredEpochEncryptionKeypair::delete(tx, id.as_id()).await,
        id @ EntityId::StoredCredential(_) => StoredCredential::delete(tx, id.as_id()).await,
        id @ EntityId::StoredBufferedCommit(_) => StoredBufferedCommit::delete(tx, id.as_id()).await,
        id @ EntityId::PersistedMlsGroup(_) => PersistedMlsGroup::delete(tx, id.as_id()).await,
        id @ EntityId::PersistedMlsPendingGroup(_) => PersistedMlsPendingGroup::delete(tx, id.as_id()).await,
        id @ EntityId::MlsPendingMessage(_) => MlsPendingMessage::delete(tx, id.as_id()).await,
        id @ EntityId::StoredE2eiEnrollment(_) => StoredE2eiEnrollment::delete(tx, id.as_id()).await,
        #[cfg(target_family = "wasm")]
        id @ EntityId::E2eiRefreshToken(_) => E2eiRefreshToken::delete(tx, id.as_id()).await,
        id @ EntityId::E2eiAcmeCA(_) => E2eiAcmeCA::delete(tx, id.as_id()).await,
        id @ EntityId::E2eiIntermediateCert(_) => E2eiIntermediateCert::delete(tx, id.as_id()).await,
        id @ EntityId::E2eiCrl(_) => E2eiCrl::delete(tx, id.as_id()).await,
        #[cfg(feature = "proteus-keystore")]
        id @ EntityId::ProteusSession(_) => ProteusSession::delete(tx, id.as_id()).await,
        #[cfg(feature = "proteus-keystore")]
        id @ EntityId::ProteusIdentity(_) => ProteusIdentity::delete(tx, id.as_id()).await,
        #[cfg(feature = "proteus-keystore")]
        id @ EntityId::ProteusPrekey(_) => ProteusPrekey::delete(tx, id.as_id()).await,
    }
}
