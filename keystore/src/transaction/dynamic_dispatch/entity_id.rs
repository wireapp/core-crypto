use core::fmt;
use std::borrow::Cow;

use rusqlite::Transaction;

use crate::CryptoKeystoreError;
use crate::CryptoKeystoreResult;
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
use crate::traits::BorrowPrimaryKey;
use crate::traits::DeletableBySearchKey as _;
use crate::traits::Entity;
use crate::traits::EntityDatabaseMutation;
use crate::traits::KeyType;
use crate::traits::OwnedKeyType as _;
use crate::transaction::dynamic_dispatch::EntityType;

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
    pub(crate) fn matches_type<E>(&self) -> bool
    where
        E: Entity,
    {
        EntityType::from_table_name(E::TABLE_NAME).is_some_and(|e_type| self.typ == e_type)
    }

    pub(crate) fn primary_key<E>(&self) -> CryptoKeystoreResult<E::PrimaryKey>
    where
        E: Entity,
    {
        // we'd prefer not to pay the cost for a runtime check, but we want more than 0 checks
        debug_assert!(
            self.matches_type::<E>(),
            "well-constructed code will never call this for a non-matching type"
        );
        E::PrimaryKey::from_bytes(&self.id).ok_or(CryptoKeystoreError::InvalidPrimaryKeyBytes(self.typ.table_name()))
    }

    pub(crate) fn from_key<E>(primary_key: Cow<'_, [u8]>) -> Option<Self>
    where
        E: Entity,
    {
        let typ = EntityType::from_table_name(E::TABLE_NAME)?;
        let id = primary_key.into_owned();
        Some(Self { typ, id })
    }

    pub(crate) fn from_entity<E>(entity: &E) -> Option<Self>
    where
        E: Entity,
    {
        Self::from_key::<E>(entity.primary_key().bytes())
    }

    pub(crate) fn from_primary_key<E>(primary_key: &E::PrimaryKey) -> Option<Self>
    where
        E: Entity,
    {
        Self::from_key::<E>(primary_key.bytes())
    }

    pub(crate) fn from_borrowed_primary_key<E>(primary_key: &E::BorrowedPrimaryKey) -> Option<Self>
    where
        E: Entity + BorrowPrimaryKey,
    {
        Self::from_key::<E>(primary_key.to_owned().bytes())
    }

    pub(crate) fn execute_delete(&self, tx: &Transaction<'_>) -> CryptoKeystoreResult<bool> {
        match self.typ {
            EntityType::HpkePrivateKey => {
                StoredHpkePrivateKey::delete(tx, &self.primary_key::<StoredHpkePrivateKey>()?)
            }
            EntityType::KeyPackage => StoredKeyPackage::delete(tx, &self.primary_key::<StoredKeyPackage>()?),
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
            EntityType::X509TrustAnchor => X509TrustAnchor::delete(tx, &self.primary_key::<X509TrustAnchor>()?),
            EntityType::X509IntermediateCert => {
                X509IntermediateCert::delete(tx, &self.primary_key::<X509IntermediateCert>()?)
            }
            EntityType::X509Crl => X509Crl::delete(tx, &self.primary_key::<X509Crl>()?),
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
