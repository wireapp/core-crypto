pub mod dynamic_dispatch;

use crate::connection::ConnectionType;
use crate::entities::mls::*;
#[cfg(feature = "proteus-keystore")]
use crate::entities::proteus::*;
use crate::entities::{ConsumerData, EntityBase, EntityFindParams, EntityTransactionExt, UniqueEntity};
use crate::transaction::dynamic_dispatch::EntityId;
use crate::{
    CryptoKeystoreError, CryptoKeystoreResult,
    connection::{Connection, DatabaseKey, FetchFromDatabase, KeystoreDatabaseConnection},
};
use async_lock::{RwLock, SemaphoreGuardArc};
use itertools::Itertools;
use std::{ops::DerefMut, sync::Arc};

/// This represents a transaction, where all operations will be done in memory and committed at the
/// end
#[derive(Debug, Clone)]
pub(crate) struct KeystoreTransaction {
    /// In-memory cache
    cache: Connection,
    deleted: Arc<RwLock<Vec<EntityId>>>,
    deleted_credentials: Arc<RwLock<Vec<Vec<u8>>>>,
    _semaphore_guard: Arc<SemaphoreGuardArc>,
}

impl KeystoreTransaction {
    pub(crate) async fn new(semaphore_guard: SemaphoreGuardArc) -> CryptoKeystoreResult<Self> {
        // We don't really care about the key and we're not going to store it anywhere.
        let key = DatabaseKey::from([0u8; 32]);
        Ok(Self {
            cache: Connection::open(ConnectionType::InMemory, &key).await?,
            deleted: Arc::new(Default::default()),
            deleted_credentials: Arc::new(Default::default()),
            _semaphore_guard: Arc::new(semaphore_guard),
        })
    }

    pub(crate) async fn save_mut<
        E: crate::entities::Entity<ConnectionType = KeystoreDatabaseConnection> + EntityTransactionExt + Sync,
    >(
        &self,
        mut entity: E,
    ) -> CryptoKeystoreResult<E> {
        entity.pre_save().await?;
        let conn = self.cache.borrow_conn().await?;
        let mut conn = conn.conn().await;
        #[cfg(target_family = "wasm")]
        let transaction = conn.new_transaction(&[E::COLLECTION_NAME]).await?;
        #[cfg(not(target_family = "wasm"))]
        let transaction = conn.transaction()?.into();
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
        let conn = self.cache.borrow_conn().await?;
        let mut conn = conn.conn().await;
        #[cfg(target_family = "wasm")]
        let transaction = conn.new_transaction(&[E::COLLECTION_NAME]).await?;
        #[cfg(not(target_family = "wasm"))]
        let transaction = conn.transaction()?.into();
        E::delete(&transaction, id.as_ref().into()).await?;
        transaction.commit_tx().await?;
        let mut deleted_list = self.deleted.write().await;
        deleted_list.push(EntityId::from_collection_name(E::COLLECTION_NAME, id.as_ref())?);
        Ok(())
    }

    pub(crate) async fn child_groups<
        E: crate::entities::Entity<ConnectionType = KeystoreDatabaseConnection> + PersistedMlsGroupExt + Sync,
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
        let conn = self.cache.borrow_conn().await?;
        let mut conn = conn.conn().await;
        #[cfg(target_family = "wasm")]
        let transaction = conn.new_transaction(&[MlsCredential::COLLECTION_NAME]).await?;
        #[cfg(not(target_family = "wasm"))]
        let transaction = conn.transaction()?.into();
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
        match cache_result {
            Some(cache_result) => Ok(Some(Some(cache_result))),
            _ => {
                let deleted_list = self.deleted.read().await;
                if deleted_list.contains(&EntityId::from_collection_name(E::COLLECTION_NAME, id)?) {
                    Ok(Some(None))
                } else {
                    Ok(None)
                }
            }
        }
    }

    pub(crate) async fn find_unique<U: UniqueEntity<ConnectionType = KeystoreDatabaseConnection>>(
        &self,
    ) -> CryptoKeystoreResult<Option<U>> {
        let cache_result = self.cache.find_unique().await;
        match cache_result {
            Ok(cache_result) => Ok(Some(cache_result)),
            _ => {
                // The deleted list doesn't have to be checked because unique entities don't implement
                // deletion, just replace. So we can directly return None.
                Ok(None)
            }
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

/// Persist all records cached in `$keystore_transaction` (first argument),
/// using a transaction on `$db` (second argument).
/// Use the provided types to read from the cache and write to the `$db`.
///
/// # Examples
/// ```rust,ignore
/// let transaction = KeystoreTransaction::new();
/// let db = Connection::new();
///
/// // Commit records of all provided types
/// commit_transaction!(
///     transaction, db,
///     [
///         (identifier_01, MlsCredential),
///         (identifier_02, MlsSignatureKeyPair),
///     ],
/// );
///
/// // Commit records of provided types in the first list. Commit records of types in the second
/// // list only if the "proteus-keystore" cargo feature is enabled.
/// commit_transaction!(
///     transaction, db,
///     [
///         (identifier_01, MlsCredential),
///         (identifier_02, MlsSignatureKeyPair),
///     ],
///     proteus_types: [
///         (identifier_03, ProteusPrekey),
///         (identifier_04, ProteusIdentity),
///         (identifier_05, ProteusSession)
///     ]
/// );
///```
macro_rules! commit_transaction {
    ($keystore_transaction:expr_2021, $db:expr_2021, [ $( ($records:ident, $entity:ty) ),*], proteus_types: [ $( ($conditional_records:ident, $conditional_entity:ty) ),*]) => {
        #[cfg(feature = "proteus-keystore")]
        commit_transaction!($keystore_transaction, $db, [ $( ($records, $entity) ),*], [ $( ($conditional_records, $conditional_entity) ),*]);

        #[cfg(not(feature = "proteus-keystore"))]
        commit_transaction!($keystore_transaction, $db, [ $( ($records, $entity) ),*]);
    };
     ($keystore_transaction:expr_2021, $db:expr_2021, $([ $( ($records:ident, $entity:ty) ),*]),*) => {
            let cached_collections = ( $( $(
            $keystore_transaction.cache.find_all::<$entity>(Default::default()).await?,
                )* )* );

             let ( $( $( $records, )* )* ) = cached_collections;

            let conn = $db.borrow_conn().await?;
            let mut conn = conn.conn().await;
            let deleted_ids = $keystore_transaction.deleted.read().await;

            let mut tables = Vec::new();
            $( $(
                if !$records.is_empty() {
                    tables.push(<$entity>::COLLECTION_NAME);
                }
            )* )*

            for deleted_id in deleted_ids.iter() {
                tables.push(deleted_id.collection_name());
            }

            if tables.is_empty() {
                log::debug!("Empty transaction was committed.");
                return Ok(());
            }

            #[cfg(target_family = "wasm")]
            let tx = conn.new_transaction(&tables).await?;
            #[cfg(not(target_family = "wasm"))]
            let tx = conn.transaction()?.into();

             $( $(
                if !$records.is_empty() {
                    for record in $records {
                        dynamic_dispatch::execute_save(&tx, &record.to_transaction_entity()).await?;
                    }
                }
             )* )*


        for deleted_id in deleted_ids.iter() {
            dynamic_dispatch::execute_delete(&tx, deleted_id).await?
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
                // (identifier_12, E2eiRefreshToken),
                (identifier_13, E2eiAcmeCA),
                (identifier_14, E2eiIntermediateCert),
                (identifier_15, E2eiCrl),
                (identifier_16, ConsumerData)
            ],
            proteus_types: [
                (identifier_17, ProteusPrekey),
                (identifier_18, ProteusIdentity),
                (identifier_19, ProteusSession)
            ]
        );

        Ok(())
    }
}
