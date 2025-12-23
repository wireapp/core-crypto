use core::fmt;
use std::borrow::Cow;

#[cfg(target_family = "wasm")]
use crate::entities::E2eiRefreshToken;
#[cfg(feature = "proteus-keystore")]
use crate::entities::{ProteusIdentity, ProteusPrekey, ProteusSession};
use crate::{
    CryptoKeystoreError, CryptoKeystoreResult,
    connection::TransactionWrapper,
    entities::{
        E2eiCrl, E2eiIntermediateCert, MlsPendingMessage, PersistedMlsGroup, PersistedMlsPendingGroup,
        StoredBufferedCommit, StoredCredential, StoredE2eiEnrollment, StoredEncryptionKeyPair,
        StoredEpochEncryptionKeypair, StoredHpkePrivateKey, StoredKeypackage, StoredPskBundle,
    },
    traits::{BorrowPrimaryKey, Entity, EntityDatabaseMutation, KeyType, OwnedKeyType as _},
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
        E: Entity,
    {
        E::PrimaryKey::from_bytes(&self.id)
            .ok_or(CryptoKeystoreError::InvalidPrimaryKeyBytes(self.typ.collection_name()))
    }

    fn from_key<E>(primary_key: Cow<'_, [u8]>) -> Self
    where
        E: Entity,
    {
        // assumption: nobody outside this crate will ever implement `Entity` on a foreign type
        let typ =
            EntityType::from_collection_name(E::COLLECTION_NAME).expect("all entities have a valid collection name");
        let id = primary_key.into_owned();
        Self { typ, id }
    }

    pub(crate) fn from_entity<E>(entity: &E) -> Self
    where
        E: Entity,
    {
        Self::from_key::<E>(entity.primary_key().bytes())
    }

    pub(crate) fn from_primary_key<E>(primary_key: &E::PrimaryKey) -> Self
    where
        E: Entity,
    {
        Self::from_key::<E>(primary_key.bytes())
    }

    pub(crate) fn from_borrowed_primary_key<E>(primary_key: &E::BorrowedPrimaryKey) -> Self
    where
        E: Entity + BorrowPrimaryKey,
    {
        Self::from_key::<E>(primary_key.to_owned().bytes())
    }

    pub(crate) fn collection_name(&self) -> &'static str {
        self.typ.collection_name()
    }

    pub(crate) async fn execute_delete(&self, tx: &TransactionWrapper<'_>) -> CryptoKeystoreResult<bool> {
        match self.typ {
            EntityType::HpkePrivateKey => {
                StoredHpkePrivateKey::delete(tx, &self.primary_key::<StoredHpkePrivateKey>()?).await
            }
            EntityType::KeyPackage => StoredKeypackage::delete(tx, &self.primary_key::<StoredKeypackage>()?).await,
            EntityType::PskBundle => StoredPskBundle::delete(tx, &self.primary_key::<StoredPskBundle>()?).await,
            EntityType::EncryptionKeyPair => {
                StoredEncryptionKeyPair::delete(tx, &self.primary_key::<StoredEncryptionKeyPair>()?).await
            }
            EntityType::EpochEncryptionKeyPair => {
                StoredEpochEncryptionKeypair::delete(tx, &self.primary_key::<StoredEpochEncryptionKeypair>()?).await
            }
            EntityType::StoredCredential => {
                StoredCredential::delete(tx, &self.primary_key::<StoredCredential>()?).await
            }
            EntityType::StoredBufferedCommit => {
                StoredBufferedCommit::delete(tx, &self.primary_key::<StoredBufferedCommit>()?).await
            }
            EntityType::PersistedMlsGroup => {
                PersistedMlsGroup::delete(tx, &self.primary_key::<PersistedMlsGroup>()?).await
            }
            EntityType::PersistedMlsPendingGroup => {
                PersistedMlsPendingGroup::delete(tx, &self.primary_key::<PersistedMlsPendingGroup>()?).await
            }
            EntityType::MlsPendingMessage => {
                let primary_key = self.primary_key::<MlsPendingMessage>()?;
                MlsPendingMessage::delete_by_conversation_id(tx, &primary_key.foreign_id).await
            }
            EntityType::StoredE2eiEnrollment => {
                StoredE2eiEnrollment::delete(tx, &self.primary_key::<StoredE2eiEnrollment>()?).await
            }
            #[cfg(target_family = "wasm")]
            EntityType::E2eiRefreshToken => {
                E2eiRefreshToken::delete(tx, &self.primary_key::<E2eiRefreshToken>()?).await
            }
            EntityType::E2eiAcmeCA => Err(CryptoKeystoreError::NotImplemented),
            EntityType::E2eiIntermediateCert => {
                E2eiIntermediateCert::delete(tx, &self.primary_key::<E2eiIntermediateCert>()?).await
            }
            EntityType::E2eiCrl => E2eiCrl::delete(tx, &self.primary_key::<E2eiCrl>()?).await,
            #[cfg(feature = "proteus-keystore")]
            EntityType::ProteusSession => ProteusSession::delete(tx, &self.primary_key::<ProteusSession>()?).await,
            #[cfg(feature = "proteus-keystore")]
            EntityType::ProteusIdentity => ProteusIdentity::delete(tx, &self.primary_key::<ProteusIdentity>()?).await,
            #[cfg(feature = "proteus-keystore")]
            EntityType::ProteusPrekey => ProteusPrekey::delete(tx, &self.primary_key::<ProteusPrekey>()?).await,
        }
    }
}
