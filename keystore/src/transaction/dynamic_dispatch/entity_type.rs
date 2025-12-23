#[cfg(target_family = "wasm")]
use crate::entities::E2eiRefreshToken;
#[cfg(feature = "proteus-keystore")]
use crate::entities::{ProteusIdentity, ProteusPrekey, ProteusSession};
use crate::{
    entities::{
        ConsumerData, E2eiAcmeCA, E2eiCrl, E2eiIntermediateCert, MlsPendingMessage, PersistedMlsGroup,
        PersistedMlsPendingGroup, StoredBufferedCommit, StoredCredential, StoredE2eiEnrollment,
        StoredEncryptionKeyPair, StoredEpochEncryptionKeypair, StoredHpkePrivateKey, StoredKeypackage, StoredPskBundle,
    },
    traits::EntityBase as _,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum EntityType {
    HpkePrivateKey,
    KeyPackage,
    PskBundle,
    EncryptionKeyPair,
    EpochEncryptionKeyPair,
    StoredCredential,
    StoredBufferedCommit,
    PersistedMlsGroup,
    PersistedMlsPendingGroup,
    MlsPendingMessage,
    StoredE2eiEnrollment,
    #[cfg(target_family = "wasm")]
    E2eiRefreshToken,
    E2eiAcmeCA,
    E2eiIntermediateCert,
    E2eiCrl,
    #[cfg(feature = "proteus-keystore")]
    ProteusIdentity,
    #[cfg(feature = "proteus-keystore")]
    ProteusPrekey,
    #[cfg(feature = "proteus-keystore")]
    ProteusSession,
    ConsumerData,
}

impl EntityType {
    pub(crate) fn from_collection_name(collection_name: &'static str) -> Option<Self> {
        match collection_name {
            StoredHpkePrivateKey::COLLECTION_NAME => Some(Self::HpkePrivateKey),
            StoredKeypackage::COLLECTION_NAME => Some(Self::KeyPackage),
            StoredPskBundle::COLLECTION_NAME => Some(Self::PskBundle),
            StoredEncryptionKeyPair::COLLECTION_NAME => Some(Self::EncryptionKeyPair),
            StoredEpochEncryptionKeypair::COLLECTION_NAME => Some(Self::EpochEncryptionKeyPair),
            StoredBufferedCommit::COLLECTION_NAME => Some(Self::StoredBufferedCommit),
            PersistedMlsGroup::COLLECTION_NAME => Some(Self::PersistedMlsGroup),
            PersistedMlsPendingGroup::COLLECTION_NAME => Some(Self::PersistedMlsPendingGroup),
            StoredCredential::COLLECTION_NAME => Some(Self::StoredCredential),
            MlsPendingMessage::COLLECTION_NAME => Some(Self::MlsPendingMessage),
            StoredE2eiEnrollment::COLLECTION_NAME => Some(Self::StoredE2eiEnrollment),
            E2eiCrl::COLLECTION_NAME => Some(Self::E2eiCrl),
            E2eiAcmeCA::COLLECTION_NAME => Some(Self::E2eiAcmeCA),
            #[cfg(target_family = "wasm")]
            E2eiRefreshToken::COLLECTION_NAME => Some(Self::E2eiRefreshToken),
            E2eiIntermediateCert::COLLECTION_NAME => Some(Self::E2eiIntermediateCert),
            #[cfg(feature = "proteus-keystore")]
            ProteusIdentity::COLLECTION_NAME => Some(Self::ProteusIdentity),
            #[cfg(feature = "proteus-keystore")]
            ProteusPrekey::COLLECTION_NAME => Some(Self::ProteusPrekey),
            #[cfg(feature = "proteus-keystore")]
            ProteusSession::COLLECTION_NAME => Some(Self::ProteusSession),
            ConsumerData::COLLECTION_NAME => Some(Self::ConsumerData),
            _ => None,
        }
    }

    pub(crate) fn collection_name(&self) -> &'static str {
        match self {
            Self::KeyPackage => StoredKeypackage::COLLECTION_NAME,
            Self::PskBundle => StoredPskBundle::COLLECTION_NAME,
            Self::EncryptionKeyPair => StoredEncryptionKeyPair::COLLECTION_NAME,
            Self::EpochEncryptionKeyPair => StoredEpochEncryptionKeypair::COLLECTION_NAME,
            Self::StoredCredential => StoredCredential::COLLECTION_NAME,
            Self::StoredBufferedCommit => StoredBufferedCommit::COLLECTION_NAME,
            Self::PersistedMlsGroup => PersistedMlsGroup::COLLECTION_NAME,
            Self::PersistedMlsPendingGroup => PersistedMlsPendingGroup::COLLECTION_NAME,
            Self::MlsPendingMessage => MlsPendingMessage::COLLECTION_NAME,
            Self::StoredE2eiEnrollment => StoredE2eiEnrollment::COLLECTION_NAME,
            #[cfg(target_family = "wasm")]
            Self::E2eiRefreshToken => E2eiRefreshToken::COLLECTION_NAME,
            Self::E2eiAcmeCA => E2eiAcmeCA::COLLECTION_NAME,
            Self::E2eiIntermediateCert => E2eiIntermediateCert::COLLECTION_NAME,
            Self::E2eiCrl => E2eiCrl::COLLECTION_NAME,
            #[cfg(feature = "proteus-keystore")]
            Self::ProteusIdentity => ProteusIdentity::COLLECTION_NAME,
            #[cfg(feature = "proteus-keystore")]
            Self::ProteusPrekey => ProteusPrekey::COLLECTION_NAME,
            #[cfg(feature = "proteus-keystore")]
            Self::ProteusSession => ProteusSession::COLLECTION_NAME,
            Self::HpkePrivateKey => StoredHpkePrivateKey::COLLECTION_NAME,
            Self::ConsumerData => ConsumerData::COLLECTION_NAME,
        }
    }
}
