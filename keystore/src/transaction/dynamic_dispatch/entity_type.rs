#[cfg(target_os = "unknown")]
use crate::entities::E2eiRefreshToken;
#[cfg(feature = "proteus-keystore")]
use crate::entities::{ProteusIdentity, ProteusPrekey, ProteusSession};
use crate::{
    entities::{
        ConsumerData, E2eiAcmeCA, E2eiCrl, E2eiIntermediateCert, MlsPendingMessage, PersistedMlsGroup,
        PersistedMlsPendingGroup, StoredBufferedCommit, StoredCredential, StoredEncryptionKeyPair,
        StoredEpochEncryptionKeypair, StoredHpkePrivateKey, StoredKeypackage, StoredPskBundle,
    },
    traits::Entity as _,
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
    #[cfg(target_os = "unknown")]
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
    pub(crate) fn from_table_name(table_name: &'static str) -> Option<Self> {
        match table_name {
            StoredHpkePrivateKey::TABLE_NAME => Some(Self::HpkePrivateKey),
            StoredKeypackage::TABLE_NAME => Some(Self::KeyPackage),
            StoredPskBundle::TABLE_NAME => Some(Self::PskBundle),
            StoredEncryptionKeyPair::TABLE_NAME => Some(Self::EncryptionKeyPair),
            StoredEpochEncryptionKeypair::TABLE_NAME => Some(Self::EpochEncryptionKeyPair),
            StoredBufferedCommit::TABLE_NAME => Some(Self::StoredBufferedCommit),
            PersistedMlsGroup::TABLE_NAME => Some(Self::PersistedMlsGroup),
            PersistedMlsPendingGroup::TABLE_NAME => Some(Self::PersistedMlsPendingGroup),
            StoredCredential::TABLE_NAME => Some(Self::StoredCredential),
            MlsPendingMessage::TABLE_NAME => Some(Self::MlsPendingMessage),
            E2eiCrl::TABLE_NAME => Some(Self::E2eiCrl),
            E2eiAcmeCA::TABLE_NAME => Some(Self::E2eiAcmeCA),
            #[cfg(target_os = "unknown")]
            E2eiRefreshToken::TABLE_NAME => Some(Self::E2eiRefreshToken),
            E2eiIntermediateCert::TABLE_NAME => Some(Self::E2eiIntermediateCert),
            #[cfg(feature = "proteus-keystore")]
            ProteusIdentity::TABLE_NAME => Some(Self::ProteusIdentity),
            #[cfg(feature = "proteus-keystore")]
            ProteusPrekey::TABLE_NAME => Some(Self::ProteusPrekey),
            #[cfg(feature = "proteus-keystore")]
            ProteusSession::TABLE_NAME => Some(Self::ProteusSession),
            ConsumerData::TABLE_NAME => Some(Self::ConsumerData),
            _ => None,
        }
    }

    pub(crate) fn table_name(&self) -> &'static str {
        match self {
            Self::KeyPackage => StoredKeypackage::TABLE_NAME,
            Self::PskBundle => StoredPskBundle::TABLE_NAME,
            Self::EncryptionKeyPair => StoredEncryptionKeyPair::TABLE_NAME,
            Self::EpochEncryptionKeyPair => StoredEpochEncryptionKeypair::TABLE_NAME,
            Self::StoredCredential => StoredCredential::TABLE_NAME,
            Self::StoredBufferedCommit => StoredBufferedCommit::TABLE_NAME,
            Self::PersistedMlsGroup => PersistedMlsGroup::TABLE_NAME,
            Self::PersistedMlsPendingGroup => PersistedMlsPendingGroup::TABLE_NAME,
            Self::MlsPendingMessage => MlsPendingMessage::TABLE_NAME,
            #[cfg(target_os = "unknown")]
            Self::E2eiRefreshToken => E2eiRefreshToken::TABLE_NAME,
            Self::E2eiAcmeCA => E2eiAcmeCA::TABLE_NAME,
            Self::E2eiIntermediateCert => E2eiIntermediateCert::TABLE_NAME,
            Self::E2eiCrl => E2eiCrl::TABLE_NAME,
            #[cfg(feature = "proteus-keystore")]
            Self::ProteusIdentity => ProteusIdentity::TABLE_NAME,
            #[cfg(feature = "proteus-keystore")]
            Self::ProteusPrekey => ProteusPrekey::TABLE_NAME,
            #[cfg(feature = "proteus-keystore")]
            Self::ProteusSession => ProteusSession::TABLE_NAME,
            Self::HpkePrivateKey => StoredHpkePrivateKey::TABLE_NAME,
            Self::ConsumerData => ConsumerData::TABLE_NAME,
        }
    }
}
