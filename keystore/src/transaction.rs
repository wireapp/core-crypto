use crate::entities::{EntityBase, ProteusIdentity, ProteusPrekey, ProteusSession, UniqueEntity};
use crate::{
    connection::{Connection, DatabaseConnection, FetchFromDatabase, KeystoreDatabaseConnection, TransactionWrapper},
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

    #[cfg(target_family = "wasm")]
    fn collection_name(&self) ->  &'static str {
        match self {
            EntityId::SignatureKeyPair(_) => MlsSignatureKeyPair::COLLECTION_NAME,
            EntityId::KeyPackage(_) => MlsKeyPackage::COLLECTION_NAME,
            EntityId::PskBundle(_) => MlsPskBundle::COLLECTION_NAME,
            EntityId::EncryptionKeyPair(_) => MlsEncryptionKeyPair::COLLECTION_NAME,
            EntityId::EpochEncryptionKeyPair(_) => MlsEpochEncryptionKeyPair::COLLECTION_NAME,
            EntityId::MlsCredential(_) => MlsCredential::COLLECTION_NAME,
            EntityId::PersistedMlsGroup(_) => PersistedMlsGroup::COLLECTION_NAME,
            EntityId::PersistedMlsPendingGroup(_) => PersistedMlsPendingGroup::COLLECTION_NAME,
            EntityId::MlsPendingMessage(_) => MlsPendingMessage::COLLECTION_NAME,
            EntityId::E2eiEnrollment(_) => E2eiEnrollment::COLLECTION_NAME,
            EntityId::E2eiRefreshToken(_) => E2eiRefreshToken::COLLECTION_NAME,
            EntityId::E2eiAcmeCA(_) => E2eiAcmeCA::COLLECTION_NAME,
            EntityId::E2eiIntermediateCert(_) => E2eiIntermediateCert::COLLECTION_NAME,
            EntityId::E2eiCrl(_) => E2eiCrl::COLLECTION_NAME,
            EntityId::ProteusIdentity(_) => ProteusIdentity::COLLECTION_NAME,
            EntityId::ProteusPrekey(_) => ProteusPrekey::COLLECTION_NAME,
            EntityId::ProteusSession(_) => ProteusSession::COLLECTION_NAME,
            EntityId::HpkePrivateKey(_) => MlsHpkePrivateKey::COLLECTION_NAME,
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
pub(crate) struct KeystoreTransaction {
    /// In-memory cache
    cache: Connection,
    deleted: Arc<RwLock<Vec<EntityId>>>,
    deleted_credentials: Arc<RwLock<Vec<Vec<u8>>>>,
}

impl KeystoreTransaction {
    pub(crate) async fn new() -> CryptoKeystoreResult<Self> {
        Ok(Self {
            // We're not using a proper key because we're not using the DB for security (memory is unencrypted).
            // We're using it for its API.
            cache: Connection::open_in_memory_with_key("core_crypto_transaction_cache", "").await?,
            deleted: Arc::new(Default::default()),
            deleted_credentials: Arc::new(Default::default()),
        })
    }

    pub(crate) async fn save_mut<
        E: crate::entities::Entity<ConnectionType = KeystoreDatabaseConnection> + EntityTransactionExt + Sync,
    >(
        &self,
        mut entity: E,
    ) -> CryptoKeystoreResult<E> {
        entity.pre_save().await?;
        let mut conn = self.cache.borrow_conn().await?;
        #[cfg(target_family = "wasm")]
        let transaction = conn.new_transaction(&[E::COLLECTION_NAME]).await?;
        #[cfg(not(target_family = "wasm"))]
        let transaction = conn.new_transaction().await?;
        entity.save(&transaction).await?;
        transaction.commit_tx().await?;
        Ok(entity)
    }

    pub(crate) async fn remove<
        E: crate::entities::Entity<ConnectionType = KeystoreDatabaseConnection> + EntityTransactionExt,
        S: AsRef<[u8]>,
    >(
        &self,
        id: S,
    ) -> CryptoKeystoreResult<()> {
        let mut conn = self.cache.borrow_conn().await?;
        #[cfg(target_family = "wasm")]
        let transaction = conn.new_transaction(&[E::COLLECTION_NAME]).await?;
        #[cfg(not(target_family = "wasm"))]
        let transaction = conn.new_transaction().await?;
        E::delete(&transaction, id.as_ref().into()).await?;
        transaction.commit_tx().await?;
        let mut deleted_list = self.deleted.write().await;
        deleted_list.push(EntityId::from_collection_name(E::COLLECTION_NAME, id.as_ref())?);
        Ok(())
    }

    pub(crate) async fn child_groups<
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
        Ok(self
            .merge_records(cached_records, persisted_records, EntityFindParams::default())
            .await)
    }

    pub(crate) async fn cred_delete_by_credential(&self, cred: Vec<u8>) -> CryptoKeystoreResult<()> {
        let mut conn = self.cache.borrow_conn().await?;
        #[cfg(target_family = "wasm")]
        let transaction = conn.new_transaction(&[MlsCredential::COLLECTION_NAME]).await?;
        #[cfg(not(target_family = "wasm"))]
        let transaction = conn.new_transaction().await?;
        MlsCredential::delete_by_credential(&transaction, cred.clone()).await?;
        transaction.commit_tx().await?;
        let mut deleted_list = self.deleted_credentials.write().await;
        deleted_list.push(cred);
        Ok(())
    }

    /// The result of this function will have different contents for different scenarios:
    /// * `Some(Some(E))` - the transaction cache contains the record
    /// * `Some(None)` - the deletion of the record has been cached
    /// * `None` - there is no information about the record in the cache
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
        Ok(self.merge_records(cached_records, persisted_records, params).await)
    }

    pub(crate) async fn find_many<E: crate::entities::Entity<ConnectionType = KeystoreDatabaseConnection>>(
        &self,
        persisted_records: Vec<E>,
        ids: &[Vec<u8>],
    ) -> CryptoKeystoreResult<Vec<E>> {
        let cached_records: Vec<E> = self.cache.find_many(ids).await?;
        Ok(self
            .merge_records(cached_records, persisted_records, EntityFindParams::default())
            .await)
    }

    /// Build a single list of unique records from two potentially overlapping lists.
    /// In case of overlap, records in `records_a` are prioritized.
    /// Identity from the perspective of this function is determined by the output of [crate::entities::Entity::merge_key].
    ///
    /// Further, the output list of records is built with respect to the provided [EntityFindParams]
    /// and the deleted records cached in this [Self] instance.     
    async fn merge_records<E: crate::entities::Entity<ConnectionType = KeystoreDatabaseConnection>>(
        &self,
        records_a: Vec<E>,
        records_b: Vec<E>,
        params: EntityFindParams,
    ) -> Vec<E> {
        let merged = records_a.into_iter().chain(records_b).unique_by(|e| e.merge_key());

        // We are consuming the iterator here to keep types of the `if` and `else` block consistent.
        // The alternative to giving up laziness here would be to use a dynamically
        // typed iterator Box<dyn Iterator<Item = E>> assigned to `merged`. The below approach
        // trades stack allocation instead of heap allocation for laziness.
        //
        // Also, we have to do this before filtering by deleted records since filter map does not
        // return an iterator that is double ended.
        let merged: Vec<E> = if params.reverse {
            merged.rev().collect()
        } else {
            merged.collect()
        };
        
        if merged.is_empty() {
            return merged;
        }

        let deleted_records = self.deleted.read().await;
        let deleted_credentials = self.deleted_credentials.read().await;
        let merged = if deleted_records.is_empty() && deleted_credentials.is_empty() {
            merged
        } else {
            merged
                .into_iter()
                .filter(|record| {
                    !Self::record_is_in_deleted_list(record, &deleted_records)
                        && !Self::credential_is_in_deleted_list(record, &deleted_credentials)
                })
                .collect()
        };

        merged
            .into_iter()
            .skip(params.offset.unwrap_or(0) as usize)
            .take(params.limit.unwrap_or(u32::MAX) as usize)
            .collect()
    }

    fn record_is_in_deleted_list<E: crate::entities::Entity<ConnectionType = KeystoreDatabaseConnection>>(
        record: &E,
        deleted_records: &[EntityId],
    ) -> bool {
        let id = EntityId::from_collection_name(E::COLLECTION_NAME, record.id_raw());
        let Ok(id) = id else { return false };
        deleted_records.contains(&id)
    }
    fn credential_is_in_deleted_list<E: crate::entities::Entity<ConnectionType = KeystoreDatabaseConnection>>(
        maybe_credential: &E,
        deleted_credentials: &[Vec<u8>],
    ) -> bool {
        let Some(credential) = maybe_credential.downcast::<MlsCredential>() else {
            return false;
        };
        deleted_credentials.contains(&credential.credential)
    }
}

macro_rules! commit_transaction {
     ($keystore_transaction:expr, $db:expr, [ $( ($records:ident, $entity:ty) ),*]) => {
        let cached_collections = ( $(
        $keystore_transaction.cache.find_all::<$entity>(Default::default()).await?,
            )* );

         let ( $( $records, )* ) = cached_collections;

        let mut conn = $db.borrow_conn().await?;
        let deleted_ids = $keystore_transaction.deleted.read().await;
        cfg_if::cfg_if! {
            if #[cfg(target_family = "wasm")] {
                let mut tables = Vec::new();
                $(
                    if !$records.is_empty() {
                        tables.push(<$entity>::COLLECTION_NAME);
                    }
                )*

                for deleted_id in deleted_ids.iter() {
                    tables.push(deleted_id.collection_name());
                }

                if tables.is_empty() {
                    // If we didn't do this early return, creating the transaction would fail.
                    // Once logging is available, we should log a warning here though. (WPB-11743)
                    return Ok(());
                }
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

        for deleted_id in deleted_ids.iter() {
            execute_delete(&tx, deleted_id).await?
        }

        for deleted_credential in $keystore_transaction.deleted_credentials.read().await.iter() {
            MlsCredential::delete_by_credential(&tx, deleted_credential.to_owned()).await?;
        }

         tx.commit_tx().await?;
     };
}

impl KeystoreTransaction {
    /// Persists all the operations in the database. It will effectively open a transaction
    /// internally, perform all the buffered operations and commit.
    pub(crate) async fn commit(&self, db: &Connection) -> Result<(), CryptoKeystoreError> {
        commit_transaction!(
            self, db,
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
