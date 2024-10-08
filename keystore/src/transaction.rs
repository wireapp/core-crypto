use crate::entities::{EntityBase, ProteusIdentity, ProteusPrekey, ProteusSession, UniqueEntity};
use crate::{
    connection::{Connection, DatabaseConnection, FetchFromDatabase, KeystoreDatabaseConnection, TransactionWrapper}
    ,
    entities::{
        E2eiAcmeCA, E2eiCrl, E2eiEnrollment, E2eiIntermediateCert, E2eiRefreshToken, EntityFindParams,
        EntityTransactionExt, MlsCredential, MlsCredentialExt, MlsEncryptionKeyPair, MlsEpochEncryptionKeyPair,
        MlsHpkePrivateKey, MlsKeyPackage, MlsPendingMessage, MlsPskBundle, MlsSignatureKeyPair, PersistedMlsGroup,
        PersistedMlsPendingGroup, StringEntityId,
    },
    CryptoKeystoreError, CryptoKeystoreResult,
};
use async_lock::RwLock;
use itertools::Itertools;
use openmls_traits::key_store::MlsEntityId;
use std::{ops::DerefMut, sync::Arc};

#[derive(Debug)]
pub enum Entity {
    SignatureKeyPair(MlsSignatureKeyPair),
    HpkePrivateKey(MlsHpkePrivateKey),
    KeyPackage(MlsKeyPackage),
    PskBundle(MlsPskBundle),
    EncryptionKeyPair(MlsEncryptionKeyPair),
    EpochEncryptionKeyPair(MlsEpochEncryptionKeyPair),
    MlsCredential(MlsCredential),
    PersistedMlsGroup(PersistedMlsGroup),
    PersistedMlsPendingGroup(PersistedMlsPendingGroup),
    MlsPendingMessage(MlsPendingMessage),
    E2eiEnrollment(E2eiEnrollment),
    E2eiRefreshToken(E2eiRefreshToken),
    E2eiAcmeCA(E2eiAcmeCA),
    E2eiIntermediateCert(E2eiIntermediateCert),
    E2eiCrl(E2eiCrl),
    ProteusIdentity(ProteusIdentity),
    ProteusPrekey(ProteusPrekey),
    ProteusSession(ProteusSession),
}

#[derive(Debug, Clone, PartialEq)]
enum EntityId {
    SignatureKeyPair(Vec<u8>),
    HpkePrivateKey(Vec<u8>),
    KeyPackage(Vec<u8>),
    PskBundle(Vec<u8>),
    EncryptionKeyPair(Vec<u8>),
    EpochEncryptionKeyPair(Vec<u8>),
    MlsCredential(Vec<u8>),
    PersistedMlsGroup(Vec<u8>),
    PersistedMlsPendingGroup(Vec<u8>),
    MlsPendingMessage(Vec<u8>),
    E2eiEnrollment(Vec<u8>),
    E2eiRefreshToken(Vec<u8>),
    E2eiAcmeCA(Vec<u8>),
    E2eiIntermediateCert(Vec<u8>),
    E2eiCrl(Vec<u8>),
    ProteusIdentity(Vec<u8>),
    ProteusPrekey(Vec<u8>),
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
            EntityId::MlsCredential(vec) => vec.as_slice().into(),
            EntityId::PersistedMlsGroup(vec) => vec.as_slice().into(),
            EntityId::PersistedMlsPendingGroup(vec) => vec.as_slice().into(),
            EntityId::MlsPendingMessage(vec) => vec.as_slice().into(),
            EntityId::E2eiEnrollment(vec) => vec.as_slice().into(),
            EntityId::E2eiRefreshToken(vec) => vec.as_slice().into(),
            EntityId::E2eiAcmeCA(vec) => vec.as_slice().into(),
            EntityId::E2eiIntermediateCert(vec) => vec.as_slice().into(),
            EntityId::E2eiCrl(vec) => vec.as_slice().into(),
            EntityId::ProteusIdentity(vec) => vec.as_slice().into(),
            EntityId::ProteusSession(id) => id.as_slice().into(),
            EntityId::ProteusPrekey(vec) => vec.as_slice().into(),
        }
    }
}

impl EntityId {
    fn from_mls_entity_id(entity_id: MlsEntityId, id: &[u8]) -> Self {
        match entity_id {
            MlsEntityId::SignatureKeyPair => Self::SignatureKeyPair(id.into()),
            MlsEntityId::HpkePrivateKey => Self::HpkePrivateKey(id.into()),
            MlsEntityId::KeyPackage => Self::KeyPackage(id.into()),
            MlsEntityId::PskBundle => Self::PskBundle(id.into()),
            MlsEntityId::EncryptionKeyPair => Self::EncryptionKeyPair(id.into()),
            MlsEntityId::EpochEncryptionKeyPair => Self::EpochEncryptionKeyPair(id.into()),
            MlsEntityId::GroupState => Self::PersistedMlsGroup(id.into()),
        }
    }

    fn from_collection_name(entity_id: &'static str, id: &[u8]) -> CryptoKeystoreResult<Self> {
        match entity_id {
            MlsSignatureKeyPair::COLLECTION_NAME => Ok(Self::SignatureKeyPair(id.into())),
            MlsHpkePrivateKey::COLLECTION_NAME => Ok(Self::HpkePrivateKey(id.into())),
            MlsKeyPackage::COLLECTION_NAME => Ok(Self::KeyPackage(id.into())),
            MlsPskBundle::COLLECTION_NAME => Ok(Self::PskBundle(id.into())),
            MlsEncryptionKeyPair::COLLECTION_NAME => Ok(Self::EncryptionKeyPair(id.into())),
            MlsEpochEncryptionKeyPair::COLLECTION_NAME => Ok(Self::EpochEncryptionKeyPair(id.into())),
            PersistedMlsGroup::COLLECTION_NAME => Ok(Self::PersistedMlsGroup(id.into())),
            PersistedMlsPendingGroup::COLLECTION_NAME => Ok(Self::PersistedMlsPendingGroup(id.into())),
            MlsCredential::COLLECTION_NAME => Ok(Self::MlsCredential(id.into())),
            MlsPendingMessage::COLLECTION_NAME => Ok(Self::MlsPendingMessage(id.into())),
            E2eiEnrollment::COLLECTION_NAME => Ok(Self::E2eiEnrollment(id.into())),
            E2eiCrl::COLLECTION_NAME => Ok(Self::E2eiCrl(id.into())),
            E2eiAcmeCA::COLLECTION_NAME => Ok(Self::E2eiAcmeCA(id.into())),
            E2eiRefreshToken::COLLECTION_NAME => Ok(Self::E2eiRefreshToken(id.into())),
            E2eiIntermediateCert::COLLECTION_NAME => Ok(Self::E2eiIntermediateCert(id.into())),
            ProteusIdentity::COLLECTION_NAME => Ok(Self::ProteusIdentity(id.into())),
            ProteusPrekey::COLLECTION_NAME => Ok(Self::ProteusPrekey(id.into())),
            ProteusSession::COLLECTION_NAME => Ok(Self::ProteusSession(id.into())),
            _ => Err(CryptoKeystoreError::NotImplemented),
        }
    }
}

async fn execute_save(tx: &TransactionWrapper<'_>, entity: &Entity) -> CryptoKeystoreResult<()> {
    match entity {
        Entity::SignatureKeyPair(mls_signature_key_pair) => mls_signature_key_pair.save(tx).await,
        Entity::HpkePrivateKey(mls_hpke_private_key) => mls_hpke_private_key.save(tx).await,
        Entity::KeyPackage(mls_key_package) => mls_key_package.save(tx).await,
        Entity::PskBundle(mls_psk_bundle) => mls_psk_bundle.save(tx).await,
        Entity::EncryptionKeyPair(mls_encryption_key_pair) => mls_encryption_key_pair.save(tx).await,
        Entity::EpochEncryptionKeyPair(mls_epoch_encryption_key_pair) => mls_epoch_encryption_key_pair.save(tx).await,
        Entity::MlsCredential(mls_credential) => mls_credential.save(tx).await,
        Entity::PersistedMlsGroup(persisted_mls_group) => persisted_mls_group.save(tx).await,
        Entity::PersistedMlsPendingGroup(persisted_mls_pending_group) => persisted_mls_pending_group.save(tx).await,
        Entity::MlsPendingMessage(mls_pending_message) => mls_pending_message.save(tx).await,
        Entity::E2eiEnrollment(e2ei_enrollment) => e2ei_enrollment.save(tx).await,
        Entity::E2eiRefreshToken(e2ei_refresh_token) => e2ei_refresh_token.replace(tx).await,
        Entity::E2eiAcmeCA(e2ei_acme_ca) => e2ei_acme_ca.replace(tx).await,
        Entity::E2eiIntermediateCert(e2ei_intermediate_cert) => e2ei_intermediate_cert.save(tx).await,
        Entity::E2eiCrl(e2ei_crl) => e2ei_crl.save(tx).await,
        Entity::ProteusSession(record) => record.save(tx).await,
        Entity::ProteusIdentity(record) => record.save(tx).await,
        Entity::ProteusPrekey(record) => record.save(tx).await,
    }
}

async fn execute_delete(tx: &TransactionWrapper<'_>, entity_id: &EntityId) -> CryptoKeystoreResult<()> {
    match entity_id {
        id @ EntityId::SignatureKeyPair(_) => MlsSignatureKeyPair::delete(tx, id.as_id()).await,
        id @ EntityId::HpkePrivateKey(_) => MlsHpkePrivateKey::delete(tx, id.as_id()).await,
        id @ EntityId::KeyPackage(_) => MlsKeyPackage::delete(tx, id.as_id()).await,
        id @ EntityId::PskBundle(_) => MlsPskBundle::delete(tx, id.as_id()).await,
        id @ EntityId::EncryptionKeyPair(_) => MlsEncryptionKeyPair::delete(tx, id.as_id()).await,
        id @ EntityId::EpochEncryptionKeyPair(_) => MlsEpochEncryptionKeyPair::delete(tx, id.as_id()).await,
        id @ EntityId::MlsCredential(_) => MlsCredential::delete(tx, id.as_id()).await,
        id @ EntityId::PersistedMlsGroup(_) => PersistedMlsGroup::delete(tx, id.as_id()).await,
        id @ EntityId::PersistedMlsPendingGroup(_) => PersistedMlsPendingGroup::delete(tx, id.as_id()).await,
        id @ EntityId::MlsPendingMessage(_) => MlsPendingMessage::delete(tx, id.as_id()).await,
        id @ EntityId::E2eiEnrollment(_) => E2eiEnrollment::delete(tx, id.as_id()).await,
        id @ EntityId::E2eiRefreshToken(_) => E2eiRefreshToken::delete(tx, id.as_id()).await,
        id @ EntityId::E2eiAcmeCA(_) => E2eiAcmeCA::delete(tx, id.as_id()).await,
        id @ EntityId::E2eiIntermediateCert(_) => E2eiIntermediateCert::delete(tx, id.as_id()).await,
        id @ EntityId::E2eiCrl(_) => E2eiCrl::delete(tx, id.as_id()).await,
        id @ EntityId::ProteusSession(_) => ProteusSession::delete(tx, id.as_id()).await,
        id @ EntityId::ProteusIdentity(_) => ProteusIdentity::delete(tx, id.as_id()).await,
        id @ EntityId::ProteusPrekey(_) => ProteusPrekey::delete(tx, id.as_id()).await,
    }
}

/// This represents a transaction, where all operations will be done in memory and committed at the
/// end
#[derive(Debug, Clone)]
pub struct KeystoreTransaction {
    /// Just needed to create the actual db transaction when committing.
    db: Connection,
    /// In-memory cache
    cache: Connection,
    deleted: Arc<RwLock<Vec<EntityId>>>,
    deleted_credentials: Arc<RwLock<Vec<Vec<u8>>>>,
}

impl KeystoreTransaction {
    pub(crate) async fn find<E>(&self, id: &[u8]) -> CryptoKeystoreResult<Option<Option<E>>>
    where
        E: crate::entities::Entity<ConnectionType = KeystoreDatabaseConnection>,
    {
        let cache_result = self.cache.find(id).await?;
        if let Some(cache_result) = cache_result {
            Ok(Some(Some(cache_result)))
        } else {
            let deleted_list = self.deleted.read().await;
            if deleted_list.contains(&EntityId::from_collection_name(E::COLLECTION_NAME, id)?) {
                Ok(Some(None))
            } else {
                Ok(None)
            }
        }
    }

    pub(crate) async fn find_unique<U: UniqueEntity<ConnectionType = KeystoreDatabaseConnection>>(
        &self,
    ) -> CryptoKeystoreResult<Option<U>> {
        let cache_result = self.cache.find_unique().await;
        if let Ok(cache_result) = cache_result {
            Ok(Some(cache_result))
        } else {
            // The deleted list doesn't have to be checked because unique entities don't implement
            // deletion, just replace. So we can directly return None.
            Ok(None)
        }
    }

    pub(crate) async fn find_all<E: crate::entities::Entity<ConnectionType = KeystoreDatabaseConnection>>(
        &self,
        persisted_records: Vec<E>,
        params: EntityFindParams,
    ) -> CryptoKeystoreResult<Vec<E>> {
        let cached_records: Vec<E> = self.cache.find_all(params.clone()).await?;
        Ok(Self::merge_records(cached_records, persisted_records, params))
    }

    pub(crate) async fn find_many<E: crate::entities::Entity<ConnectionType = KeystoreDatabaseConnection>>(
        &self,
        persisted_records: Vec<E>,
        ids: &[Vec<u8>],
    ) -> CryptoKeystoreResult<Vec<E>> {
        let cached_records: Vec<E> = self.cache.find_many(ids).await?;
        Ok(Self::merge_records(
            cached_records,
            persisted_records,
            EntityFindParams::default(),
        ))
    }

    fn merge_records<E: crate::entities::Entity<ConnectionType = KeystoreDatabaseConnection>>(
        records_a: Vec<E>,
        records_b: Vec<E>,
        params: EntityFindParams,
    ) -> Vec<E> {
        let merged = records_a
            .into_iter()
            .chain(records_b)
            .unique_by(|e| e.id_raw().to_vec());

        // The alternative to giving up laziness here would be to use a dynamically
        // typed iterator Box<dyn Iterator<Item = E>> assigned to `merged`. The below approach
        // trades stack allocation instead of heap allocation for laziness.
        let merged: Vec<E> = if params.reverse {
            merged.rev().collect()
        } else {
            merged.collect()
        };

        merged
            .into_iter()
            .skip(params.offset.unwrap_or(0) as usize)
            .take(params.limit.unwrap_or(u32::MAX) as usize)
            .collect()
    }
}

macro_rules! commit_transaction {
     ($keystore_transaction:expr, [ $( ($records:ident, $entity:ty) ),*]) => {
        let cached_collections = ( $(
        $keystore_transaction.cache.find_all::<$entity>(Default::default()).await?,
            )* );

         let ( $( $records, )* ) = cached_collections;

        let mut conn = $keystore_transaction.db.borrow_conn().await?;
        cfg_if::cfg_if! {
            if #[cfg(target_family = "wasm")] {
                let mut tables = Vec::new();
                $(
                    if !$records.is_empty() {
                        tables.push(<$entity>::COLLECTION_NAME);
                    }
                )*
                let tx = conn.new_transaction(&tables).await?;
            } else {
                let tx = conn.new_transaction().await?;
            }
        }

         $(
            if !$records.is_empty() {
                for record in $records {
                    execute_save(&tx, &record.to_transaction_entity()).await?;
                }
            }
         )*

        for deleted_id in $keystore_transaction.deleted.read().await.iter() {
            execute_delete(&tx, deleted_id).await?
        }

        for deleted_credential in $keystore_transaction.deleted_credentials.read().await.iter() {
            MlsCredential::delete_by_credential(&tx, deleted_credential.to_owned()).await?;
        }

         tx.commit_tx().await?;
     };
}

impl KeystoreTransaction {
    pub async fn new(db: Connection) -> CryptoKeystoreResult<Self> {
        Ok(Self {
            db,
            // We're not using a proper key because we're not using the DB for security (memory is unencrypted).
            // We're using it for its API.
            cache: Connection::open_in_memory_with_key("core_crypto_transaction_cache", "").await?,
            deleted: Arc::new(Default::default()),
            deleted_credentials: Arc::new(Default::default()),
        })
    }

    pub async fn save<
        E: crate::entities::Entity<ConnectionType = KeystoreDatabaseConnection> + Sync + EntityTransactionExt,
    >(
        &self,
        entity: E,
    ) -> CryptoKeystoreResult<()> {
        let mut conn = self.cache.borrow_conn().await?;
        let transaction = conn.new_transaction().await?;
        entity.save(&transaction).await?;
        transaction.commit_tx().await
    }

    pub async fn save_mut<
        E: crate::entities::Entity<ConnectionType = KeystoreDatabaseConnection> + EntityTransactionExt + Sync,
    >(
        &self,
        mut entity: E,
    ) -> CryptoKeystoreResult<E> {
        entity.pre_save().await?;
        let mut conn = self.cache.borrow_conn().await?;
        let transaction = conn.new_transaction().await?;
        entity.save(&transaction).await?;
        transaction.commit_tx().await?;
        Ok(entity)
    }

    pub async fn remove<
        E: crate::entities::Entity<ConnectionType = KeystoreDatabaseConnection> + EntityTransactionExt,
        S: AsRef<[u8]>,
    >(
        &self,
        id: S,
    ) -> CryptoKeystoreResult<()> {
        let mut conn = self.cache.borrow_conn().await?;
        let transaction = conn.new_transaction().await?;
        E::delete(&transaction, id.as_ref().into()).await?;
        transaction.commit_tx().await?;
        let mut deleted_list = self.deleted.write().await;
        deleted_list.push(EntityId::from_collection_name(E::COLLECTION_NAME, id.as_ref())?);
        Ok(())
    }

    pub async fn child_groups<
        E: crate::entities::Entity<ConnectionType = KeystoreDatabaseConnection>
            + crate::entities::PersistedMlsGroupExt
            + Sync,
    >(
        &self,
        entity: E,
        persisted_records: Vec<E>,
    ) -> CryptoKeystoreResult<Vec<E>> {
        let mut conn = self.cache.borrow_conn().await?;
        let cached_records = entity.child_groups(conn.deref_mut()).await?;
        Ok(Self::merge_records(
            cached_records,
            persisted_records,
            EntityFindParams::default(),
        ))
    }

    pub async fn cred_delete_by_credential(&self, cred: Vec<u8>) -> CryptoKeystoreResult<()> {
        let mut conn = self.cache.borrow_conn().await?;
        let transaction = conn.new_transaction().await?;
        MlsCredential::delete_by_credential(&transaction, cred.clone()).await?;
        transaction.commit_tx().await?;
        let mut deleted_list = self.deleted_credentials.write().await;
        deleted_list.push(cred);
        Ok(())
    }

    /// Persists all the operations in the database. It will effectively open a transaction
    /// internally, perform all the buffered operations and commit.
    ///
    /// TODO: currently only MLS is supported. Implement for proteus. For that, remove the default
    /// save, insert and delete functions in the `EntityBase` trait
    /// FIXME: implement a transaction wrapper for the wasm platform to await on the transaction
    pub async fn commit(&self) -> Result<(), CryptoKeystoreError> {
        commit_transaction!(
            self,
            [
                (identifier_01, MlsCredential),
                (identifier_02, MlsSignatureKeyPair),
                (identifier_03, MlsHpkePrivateKey),
                (identifier_04, MlsEncryptionKeyPair),
                (identifier_05, MlsEpochEncryptionKeyPair),
                (identifier_06, MlsPskBundle),
                (identifier_07, MlsKeyPackage),
                (identifier_08, PersistedMlsGroup),
                (identifier_09, PersistedMlsPendingGroup),
                (identifier_10, MlsPendingMessage),
                (identifier_11, E2eiEnrollment),
                (identifier_12, E2eiRefreshToken),
                (identifier_13, E2eiAcmeCA),
                (identifier_14, E2eiIntermediateCert),
                (identifier_15, E2eiCrl),
                (identifier_16, ProteusPrekey),
                (identifier_17, ProteusIdentity),
                (identifier_18, ProteusSession)
            ]
        );

        Ok(())
    }
}
