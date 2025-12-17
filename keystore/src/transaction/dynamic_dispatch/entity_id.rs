#[cfg(target_family = "wasm")]
use crate::entities::E2eiRefreshToken;
#[cfg(feature = "proteus-keystore")]
use crate::entities::{ProteusIdentity, ProteusPrekey, ProteusSession};
use crate::{
    CryptoKeystoreError, CryptoKeystoreResult,
    connection::TransactionWrapper,
    entities::{
        E2eiAcmeCA, E2eiCrl, E2eiIntermediateCert, MlsPendingMessage, PersistedMlsGroup, PersistedMlsPendingGroup,
        StoredBufferedCommit, StoredCredential, StoredE2eiEnrollment, StoredEncryptionKeyPair,
        StoredEpochEncryptionKeypair, StoredHpkePrivateKey, StoredKeypackage, StoredPskBundle,
    },
    traits::{Entity, EntityDatabaseMutation, KeyType as _, OwnedKeyType as _},
    transaction::dynamic_dispatch::EntityType,
};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct EntityId {
    typ: EntityType,
    id: Vec<u8>,
}

impl EntityId {
    fn primary_key<E>(&self) -> CryptoKeystoreResult<E::PrimaryKey>
    where
        E: Entity,
    {
        <E as Entity>::PrimaryKey::from_bytes(&self.id)
            .ok_or(CryptoKeystoreError::InvalidPrimaryKeyBytes(self.typ.collection_name()))
    }

    pub(crate) fn from_entity<E>(entity: &E) -> Self
    where
        E: Entity,
    {
        // assumption: nobody outside this crate will ever implement `Entity` on a foreign type
        let typ =
            EntityType::from_collection_name(E::COLLECTION_NAME).expect("all entities have a valid collection name");
        let id = entity.primary_key().bytes().into_owned();
        Self { typ, id }
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
                MlsPendingMessage::delete(tx, &self.primary_key::<MlsPendingMessage>()?).await
            }
            EntityType::StoredE2eiEnrollment => {
                StoredE2eiEnrollment::delete(tx, &self.primary_key::<StoredE2eiEnrollment>()?).await
            }
            #[cfg(target_family = "wasm")]
            EntityType::E2eiRefreshToken => {
                E2eiRefreshToken::delete(tx, &self.primary_key::<E2eiRefreshToken>()?).await
            }
            EntityType::E2eiAcmeCA => E2eiAcmeCA::delete(tx, &self.primary_key::<E2eiAcmeCA>()?).await,
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
