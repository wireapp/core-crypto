use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::sync::Arc;

use async_lock::{RwLock, SemaphoreGuardArc};
use itertools::Itertools;
use zeroize::Zeroizing;

use crate::connection::KeystoreDatabaseConnection;
use crate::entities::mls::*;
#[cfg(feature = "proteus-keystore")]
use crate::entities::proteus::*;
use crate::entities::{ConsumerData, EntityBase, EntityFindParams, EntityTransactionExt, UniqueEntity};
use crate::transaction::dynamic_dispatch::EntityId;
use crate::{CryptoKeystoreError, CryptoKeystoreResult, connection::Database};

pub mod dynamic_dispatch;

#[derive(Debug, Default, derive_more::Deref, derive_more::DerefMut)]
struct InMemoryTable(HashMap<Vec<u8>, Zeroizing<Vec<u8>>>);

type InMemoryCache = Arc<RwLock<HashMap<String, InMemoryTable>>>;

/// This represents a transaction, where all operations will be done in memory and committed at the
/// end
#[derive(Debug, Clone)]
pub(crate) struct KeystoreTransaction {
    cache: InMemoryCache,
    deleted: Arc<RwLock<Vec<EntityId>>>,
    deleted_credentials: Arc<RwLock<Vec<Vec<u8>>>>,
    _semaphore_guard: Arc<SemaphoreGuardArc>,
}

impl KeystoreTransaction {
    pub(crate) async fn new(semaphore_guard: SemaphoreGuardArc) -> CryptoKeystoreResult<Self> {
        Ok(Self {
            cache: Default::default(),
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
        let mut cache_guard = self.cache.write().await;
        let table = cache_guard.entry(E::COLLECTION_NAME.to_string()).or_default();
        let serialized = postcard::to_stdvec(&entity)?;
        // Use merge_key() because `id_raw()` is not always unique for records.
        // For `MlsCredential`, `id_raw()` is the `CLientId`.
        // For `MlsPendingMessage` it's the id of the group it belongs to.
        table.insert(entity.merge_key(), Zeroizing::new(serialized));
        Ok(entity)
    }

    pub(crate) async fn remove<
        E: crate::entities::Entity<ConnectionType = KeystoreDatabaseConnection> + EntityTransactionExt,
        S: AsRef<[u8]>,
    >(
        &self,
        id: S,
    ) -> CryptoKeystoreResult<()> {
        let mut cache_guard = self.cache.write().await;
        if let Entry::Occupied(mut table) = cache_guard.entry(E::COLLECTION_NAME.to_string())
            && let Entry::Occupied(cached_record) = table.get_mut().entry(id.as_ref().to_vec())
        {
            cached_record.remove_entry();
        };

        let mut deleted_list = self.deleted.write().await;
        deleted_list.push(EntityId::from_collection_name(E::COLLECTION_NAME, id.as_ref())?);
        Ok(())
    }

    pub(crate) async fn child_groups<E>(&self, entity: E, persisted_records: Vec<E>) -> CryptoKeystoreResult<Vec<E>>
    where
        E: crate::entities::Entity<ConnectionType = KeystoreDatabaseConnection> + PersistedMlsGroupExt + Sync,
    {
        // First get all raw groups from the cache, then deserialize them to enable filtering by there parent id
        // matching `entity.id_raw()`.
        let cached_records = self
            .find_all_in_cache()
            .await?
            .into_iter()
            .filter(|maybe_child: &E| {
                maybe_child
                    .parent_id()
                    .map(|parent_id| parent_id == entity.id_raw())
                    .unwrap_or_default()
            })
            .collect();

        Ok(self
            .merge_records(cached_records, persisted_records, EntityFindParams::default())
            .await)
    }

    pub(crate) async fn cred_delete_by_credential(&self, cred: Vec<u8>) -> CryptoKeystoreResult<()> {
        let mut cache_guard = self.cache.write().await;
        if let Entry::Occupied(mut table) = cache_guard.entry(MlsCredential::COLLECTION_NAME.to_string()) {
            table.get_mut().retain(|_, value| **value != cred);
        }

        let mut deleted_list = self.deleted_credentials.write().await;
        deleted_list.push(cred);
        Ok(())
    }

    pub(crate) async fn remove_pending_messages_by_conversation_id(
        &self,
        conversation_id: impl AsRef<[u8]> + Send,
    ) -> CryptoKeystoreResult<()> {
        // We cannot return an error from `retain()`, so we've got to do this dance with a mutable result.
        let mut result = Ok(());

        let mut cache_guard = self.cache.write().await;
        if let Entry::Occupied(mut table) = cache_guard.entry(MlsPendingMessage::COLLECTION_NAME.to_string()) {
            table.get_mut().retain(|_key, record_bytes| {
                postcard::from_bytes::<MlsPendingMessage>(record_bytes)
                    .map(|pending_message| pending_message.foreign_id != conversation_id.as_ref())
                    .inspect_err(|err| result = Err(err.clone()))
                    .unwrap_or(false)
            });
        }

        let mut deleted_list = self.deleted.write().await;
        deleted_list.push(EntityId::from_collection_name(
            MlsPendingMessage::COLLECTION_NAME,
            conversation_id.as_ref(),
        )?);
        result.map_err(Into::into)
    }

    pub(crate) async fn find_pending_messages_by_conversation_id(
        &self,
        conversation_id: &[u8],
        persisted_records: Vec<MlsPendingMessage>,
    ) -> CryptoKeystoreResult<Vec<MlsPendingMessage>> {
        let cached_records = self
            .find_all_in_cache::<MlsPendingMessage>()
            .await?
            .into_iter()
            .filter(|pending_message| pending_message.foreign_id == conversation_id)
            .collect();
        let merged_records = self
            .merge_records(cached_records, persisted_records, Default::default())
            .await;
        Ok(merged_records)
    }

    async fn find_in_cache<E>(&self, id: &[u8]) -> CryptoKeystoreResult<Option<E>>
    where
        E: crate::entities::Entity<ConnectionType = KeystoreDatabaseConnection>,
    {
        let cache_guard = self.cache.read().await;
        cache_guard
            .get(E::COLLECTION_NAME)
            .and_then(|table| {
                table
                    .get(id)
                    .map(|record| -> CryptoKeystoreResult<_> { postcard::from_bytes::<E>(record).map_err(Into::into) })
            })
            .transpose()
    }

    /// The result of this function will have different contents for different scenarios:
    /// * `Some(Some(E))` - the transaction cache contains the record
    /// * `Some(None)` - the deletion of the record has been cached
    /// * `None` - there is no information about the record in the cache
    pub(crate) async fn find<E>(&self, id: &[u8]) -> CryptoKeystoreResult<Option<Option<E>>>
    where
        E: crate::entities::Entity<ConnectionType = KeystoreDatabaseConnection>,
    {
        let maybe_cached_record = self.find_in_cache(id).await?;
        if let Some(cached_record) = maybe_cached_record {
            return Ok(Some(Some(cached_record)));
        }

        let deleted_list = self.deleted.read().await;
        if deleted_list.contains(&EntityId::from_collection_name(E::COLLECTION_NAME, id)?) {
            return Ok(Some(None));
        }

        Ok(None)
    }

    pub(crate) async fn find_unique<U: UniqueEntity<ConnectionType = KeystoreDatabaseConnection>>(
        &self,
    ) -> CryptoKeystoreResult<Option<U>> {
        #[cfg(target_family = "wasm")]
        let id = &U::ID;
        #[cfg(not(target_family = "wasm"))]
        let id = &[U::ID as u8];
        let maybe_cached_record = self.find_in_cache::<U>(id).await?;
        match maybe_cached_record {
            Some(cached_record) => Ok(Some(cached_record)),
            _ => {
                // The deleted list doesn't have to be checked because unique entities don't implement
                // deletion, just replace. So we can directly return None.
                Ok(None)
            }
        }
    }

    async fn find_all_in_cache<E: crate::entities::Entity<ConnectionType = KeystoreDatabaseConnection>>(
        &self,
    ) -> CryptoKeystoreResult<Vec<E>> {
        let cache_guard = self.cache.read().await;
        let cached_records = cache_guard
            .get(E::COLLECTION_NAME)
            .map(|table| {
                table
                    .values()
                    .map(|record| postcard::from_bytes::<E>(record).map_err(Into::into))
                    .collect::<CryptoKeystoreResult<Vec<_>>>()
            })
            .transpose()?
            .unwrap_or_default();
        Ok(cached_records)
    }

    pub(crate) async fn find_all<E: crate::entities::Entity<ConnectionType = KeystoreDatabaseConnection>>(
        &self,
        persisted_records: Vec<E>,
        params: EntityFindParams,
    ) -> CryptoKeystoreResult<Vec<E>> {
        let cached_records = self.find_all_in_cache().await?;
        let merged_records = self.merge_records(cached_records, persisted_records, params).await;
        Ok(merged_records)
    }

    pub(crate) async fn find_many<E: crate::entities::Entity<ConnectionType = KeystoreDatabaseConnection>>(
        &self,
        persisted_records: Vec<E>,
        ids: &[Vec<u8>],
    ) -> CryptoKeystoreResult<Vec<E>> {
        let records = self
            .find_all(persisted_records, EntityFindParams::default())
            .await?
            .into_iter()
            .filter(|record| ids.contains(&record.id_raw().to_vec()))
            .collect();
        Ok(records)
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
        let mut merged = records_a.into_iter().chain(records_b).unique_by(|e| e.merge_key());

        let deleted_records = self.deleted.read().await;
        let deleted_credentials = self.deleted_credentials.read().await;

        let merged: &mut dyn Iterator<Item = E> = if params.reverse { &mut merged.rev() } else { &mut merged };

        merged
            .filter(|record| {
                !Self::record_is_in_deleted_list(record, &deleted_records)
                    && !Self::credential_is_in_deleted_list(record, &deleted_credentials)
            })
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
            $keystore_transaction.find_all_in_cache::<$entity>().await?,
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
    pub(crate) async fn commit(&self, db: &Database) -> Result<(), CryptoKeystoreError> {
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
