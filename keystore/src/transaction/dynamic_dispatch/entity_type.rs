use crate::entities::ConsumerData;
use crate::entities::MlsPendingMessage;
use crate::entities::PersistedMlsGroup;
use crate::entities::PersistedMlsPendingGroup;
#[cfg(feature = "proteus-keystore")]
use crate::entities::ProteusIdentity;
#[cfg(feature = "proteus-keystore")]
use crate::entities::ProteusPrekey;
#[cfg(feature = "proteus-keystore")]
use crate::entities::ProteusSession;
use crate::entities::StoredBufferedCommit;
use crate::entities::StoredCredential;
use crate::entities::StoredEncryptionKeyPair;
use crate::entities::StoredEpochEncryptionKeypair;
use crate::entities::StoredHpkePrivateKey;
use crate::entities::StoredKeyPackage;
use crate::entities::StoredPskBundle;
use crate::entities::X509Crl;
use crate::entities::X509IntermediateCert;
use crate::entities::X509TrustAnchor;
use crate::traits::Entity as _;

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
    X509TrustAnchor,
    X509IntermediateCert,
    X509Crl,
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
            StoredKeyPackage::TABLE_NAME => Some(Self::KeyPackage),
            StoredPskBundle::TABLE_NAME => Some(Self::PskBundle),
            StoredEncryptionKeyPair::TABLE_NAME => Some(Self::EncryptionKeyPair),
            StoredEpochEncryptionKeypair::TABLE_NAME => Some(Self::EpochEncryptionKeyPair),
            StoredBufferedCommit::TABLE_NAME => Some(Self::StoredBufferedCommit),
            PersistedMlsGroup::TABLE_NAME => Some(Self::PersistedMlsGroup),
            PersistedMlsPendingGroup::TABLE_NAME => Some(Self::PersistedMlsPendingGroup),
            StoredCredential::TABLE_NAME => Some(Self::StoredCredential),
            MlsPendingMessage::TABLE_NAME => Some(Self::MlsPendingMessage),
            X509Crl::TABLE_NAME => Some(Self::X509Crl),
            X509IntermediateCert::TABLE_NAME => Some(Self::X509IntermediateCert),
            X509TrustAnchor::TABLE_NAME => Some(Self::X509TrustAnchor),
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
            Self::KeyPackage => StoredKeyPackage::TABLE_NAME,
            Self::PskBundle => StoredPskBundle::TABLE_NAME,
            Self::EncryptionKeyPair => StoredEncryptionKeyPair::TABLE_NAME,
            Self::EpochEncryptionKeyPair => StoredEpochEncryptionKeypair::TABLE_NAME,
            Self::StoredCredential => StoredCredential::TABLE_NAME,
            Self::StoredBufferedCommit => StoredBufferedCommit::TABLE_NAME,
            Self::PersistedMlsGroup => PersistedMlsGroup::TABLE_NAME,
            Self::PersistedMlsPendingGroup => PersistedMlsPendingGroup::TABLE_NAME,
            Self::MlsPendingMessage => MlsPendingMessage::TABLE_NAME,
            Self::X509IntermediateCert => X509IntermediateCert::TABLE_NAME,
            Self::X509TrustAnchor => X509TrustAnchor::TABLE_NAME,
            Self::X509Crl => X509Crl::TABLE_NAME,
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
