use core::fmt;
use std::borrow::Cow;

use rusqlite::Transaction;

#[cfg(target_os = "unknown")]
use crate::entities::E2eiRefreshToken;
#[cfg(feature = "proteus-keystore")]
use crate::entities::{ProteusIdentity, ProteusPrekey, ProteusSession};
use crate::{
    CryptoKeystoreError, CryptoKeystoreResult,
    entities::{
        ConsumerData, E2eiAcmeCA, E2eiCrl, E2eiIntermediateCert, MlsPendingMessage, PersistedMlsGroup,
        PersistedMlsPendingGroup, StoredBufferedCommit, StoredCredential, StoredE2eiEnrollment,
        StoredEncryptionKeyPair, StoredEpochEncryptionKeypair, StoredHpkePrivateKey, StoredKeypackage, StoredPskBundle,
    },
    traits::{
        BorrowPrimaryKey, KeyType, OwnedKeyType as _, UnifiedDeletableBySearchKey as _, UnifiedEntity,
        UnifiedEntityDatabaseMutation,
    },
    transaction::dynamic_dispatch::EntityType,
};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct EntityId {
    typ: EntityType,
    id: Vec<u8>,
}

impl fmt::Display for EntityId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Self { typ, id } = self;
        write!(f, "{typ:?}: {}", hex::encode(id))
    }
}

impl EntityId {
    fn primary_key<E>(&self) -> CryptoKeystoreResult<E::PrimaryKey>
    where
        E: UnifiedEntity,
    {
        E::PrimaryKey::from_bytes(&self.id)
            .ok_or(CryptoKeystoreError::InvalidPrimaryKeyBytes(self.typ.collection_name()))
    }

    pub(crate) fn from_key<E>(primary_key: Cow<'_, [u8]>) -> Option<Self>
    where
        E: UnifiedEntity,
    {
        let typ = EntityType::from_collection_name(E::COLLECTION_NAME)?;
        let id = primary_key.into_owned();
        Some(Self { typ, id })
    }

    pub(crate) fn from_entity<E>(entity: &E) -> Option<Self>
    where
        E: UnifiedEntity,
    {
        Self::from_key::<E>(entity.primary_key().bytes())
    }

    pub(crate) fn from_primary_key<E>(primary_key: &E::PrimaryKey) -> Option<Self>
    where
        E: UnifiedEntity,
    {
        Self::from_key::<E>(primary_key.bytes())
    }

    pub(crate) fn from_borrowed_primary_key<E>(primary_key: &E::BorrowedPrimaryKey) -> Option<Self>
    where
        E: UnifiedEntity + BorrowPrimaryKey,
    {
        Self::from_key::<E>(primary_key.to_owned().bytes())
    }

    pub(crate) fn collection_name(&self) -> &'static str {
        self.typ.collection_name()
    }

    pub(crate) fn execute_delete(&self, tx: &Transaction<'_>) -> CryptoKeystoreResult<bool> {
        match self.typ {
            EntityType::HpkePrivateKey => {
                StoredHpkePrivateKey::delete(tx, &self.primary_key::<StoredHpkePrivateKey>()?)
            }
            EntityType::KeyPackage => StoredKeypackage::delete(tx, &self.primary_key::<StoredKeypackage>()?),
            EntityType::PskBundle => StoredPskBundle::delete(tx, &self.primary_key::<StoredPskBundle>()?),
            EntityType::EncryptionKeyPair => {
                StoredEncryptionKeyPair::delete(tx, &self.primary_key::<StoredEncryptionKeyPair>()?)
            }
            EntityType::EpochEncryptionKeyPair => {
                StoredEpochEncryptionKeypair::delete(tx, &self.primary_key::<StoredEpochEncryptionKeypair>()?)
            }
            EntityType::StoredCredential => StoredCredential::delete(tx, &self.primary_key::<StoredCredential>()?),
            EntityType::StoredBufferedCommit => {
                StoredBufferedCommit::delete(tx, &self.primary_key::<StoredBufferedCommit>()?)
            }
            EntityType::PersistedMlsGroup => PersistedMlsGroup::delete(tx, &self.primary_key::<PersistedMlsGroup>()?),
            EntityType::PersistedMlsPendingGroup => {
                PersistedMlsPendingGroup::delete(tx, &self.primary_key::<PersistedMlsPendingGroup>()?)
            }
            EntityType::MlsPendingMessage => {
                MlsPendingMessage::delete_all_matching(tx, &self.id.as_slice().into()).map(|_| false)
            }
            EntityType::StoredE2eiEnrollment => {
                StoredE2eiEnrollment::delete(tx, &self.primary_key::<StoredE2eiEnrollment>()?)
            }
            #[cfg(target_os = "unknown")]
            EntityType::E2eiRefreshToken => E2eiRefreshToken::delete(tx, &self.primary_key::<E2eiRefreshToken>()?),
            EntityType::E2eiAcmeCA => E2eiAcmeCA::delete(tx, &self.primary_key::<E2eiAcmeCA>()?),
            EntityType::E2eiIntermediateCert => {
                E2eiIntermediateCert::delete(tx, &self.primary_key::<E2eiIntermediateCert>()?)
            }
            EntityType::E2eiCrl => E2eiCrl::delete(tx, &self.primary_key::<E2eiCrl>()?),
            #[cfg(feature = "proteus-keystore")]
            EntityType::ProteusSession => ProteusSession::delete(tx, &self.primary_key::<ProteusSession>()?),
            #[cfg(feature = "proteus-keystore")]
            EntityType::ProteusIdentity => ProteusIdentity::delete(tx, &self.primary_key::<ProteusIdentity>()?),
            #[cfg(feature = "proteus-keystore")]
            EntityType::ProteusPrekey => ProteusPrekey::delete(tx, &self.primary_key::<ProteusPrekey>()?),
            EntityType::ConsumerData => ConsumerData::delete(tx, &self.primary_key::<ConsumerData>()?),
        }
    }
}
