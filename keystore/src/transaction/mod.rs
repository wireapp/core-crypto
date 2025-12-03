use std::{
    collections::{HashMap, hash_map::Entry},
    sync::Arc,
};

use async_lock::{RwLock, SemaphoreGuardArc};
use itertools::Itertools;
use zeroize::Zeroizing;

#[cfg(feature = "proteus-keystore")]
use crate::entities::proteus::*;
use crate::{
    CryptoKeystoreError, CryptoKeystoreResult, Entity, EntityTransactionExt, KeyType, UniqueEntity,
    connection::{Database, KeystoreDatabaseConnection},
    entities::{ConsumerData, mls::*},
    transaction::dynamic_dispatch::EntityId,
};

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
    /// Construct a new transaction, handing over the semaphore guard.
    ///
    /// When this transaction is dropped, the guard will be released.
    pub(crate) async fn new(semaphore_guard: SemaphoreGuardArc) -> CryptoKeystoreResult<Self> {
        Ok(Self {
            cache: Default::default(),
            deleted: Arc::new(Default::default()),
            deleted_credentials: Arc::new(Default::default()),
            _semaphore_guard: Arc::new(semaphore_guard),
        })
    }

    /// Save and modify the provided entity. Return the modified entity.
    ///
    /// This allows for e.g. updating timestamps to the first-saved time.
    pub(crate) async fn save_mut<'a, E>(&self, mut entity: E) -> CryptoKeystoreResult<E>
    where
        E: Entity<ConnectionType = KeystoreDatabaseConnection> + EntityTransactionExt<'a> + Send + Sync,
    {
        entity.pre_save().await?;
        let mut cache_guard = self.cache.write().await;
        let table = cache_guard.entry(E::COLLECTION_NAME.to_string()).or_default();
        let serialized = postcard::to_stdvec(&entity)?;
        // Use merge_key() because `id_raw()` is not always unique for records.
        // For `StoredCredential`, `id_raw()` is the `CLientId`.
        // For `MlsPendingMessage` it's the id of the group it belongs to.
        table.insert(entity.primary_key().bytes().into_owned(), Zeroizing::new(serialized));
        Ok(entity)
    }

    /// Remove the given entity from the database by its ID.
    pub(crate) async fn remove<'a, E>(&self, id: &<E as Entity>::PrimaryKey) -> CryptoKeystoreResult<()>
    where
        E: Entity<ConnectionType = KeystoreDatabaseConnection> + EntityTransactionExt<'a> + Sync,
    {
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
        E: Entity<ConnectionType = KeystoreDatabaseConnection> + PersistedMlsGroupExt + Sync,
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

        Ok(self.merge_records(cached_records, persisted_records).await)
    }

    pub(crate) async fn cred_delete_by_credential(&self, cred: Vec<u8>) -> CryptoKeystoreResult<()> {
        let mut cache_guard = self.cache.write().await;
        if let Entry::Occupied(mut table) = cache_guard.entry(StoredCredential::COLLECTION_NAME.to_string()) {
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
        let merged_records = self.merge_records(cached_records, persisted_records).await;
        Ok(merged_records)
    }

    async fn find_in_cache<E>(&self, id: &[u8]) -> CryptoKeystoreResult<Option<E>>
    where
        E: Entity<ConnectionType = KeystoreDatabaseConnection>,
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
        E: Entity<ConnectionType = KeystoreDatabaseConnection>,
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

    pub(crate) async fn find_unique<U>(&self) -> CryptoKeystoreResult<Option<U>>
    where
        U: UniqueEntity<ConnectionType = KeystoreDatabaseConnection>,
    {
        let maybe_cached_record = self.find_in_cache::<U>(U::ID).await?;
        match maybe_cached_record {
            Some(cached_record) => Ok(Some(cached_record)),
            _ => {
                // The deleted list doesn't have to be checked because unique entities don't implement
                // deletion, just replace. So we can directly return None.
                Ok(None)
            }
        }
    }

    async fn find_all_in_cache<E>(&self) -> CryptoKeystoreResult<Vec<E>>
    where
        E: Entity<ConnectionType = KeystoreDatabaseConnection>,
    {
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

    pub(crate) async fn find_all<E>(&self, persisted_records: Vec<E>) -> CryptoKeystoreResult<Vec<E>>
    where
        E: Entity<ConnectionType = KeystoreDatabaseConnection>,
    {
        let cached_records = self.find_all_in_cache().await?;
        let merged_records = self.merge_records(cached_records, persisted_records).await;
        Ok(merged_records)
    }

    /// Build a single list of unique records from two potentially overlapping lists.
    /// In case of overlap, records in `records_a` are prioritized.
    /// Identity from the perspective of this function is determined by the output of
    /// [crate::entities::Entity::merge_key].
    ///
    /// Further, the output list of records is built with respect to the provided [EntityFindParams]
    /// and the deleted records cached in this [Self] instance.
    async fn merge_records<E>(
        &self,
        records_a: impl IntoIterator<Item = E>,
        records_b: impl IntoIterator<Item = E>,
    ) -> impl Iterator<Item = E>
    where
        E: Entity<ConnectionType = KeystoreDatabaseConnection>,
        <E as Entity>::PrimaryKey: std::hash::Hash,
    {
        let mut merged = records_a.into_iter().chain(records_b).unique_by(|e| e.primary_key());

        let deleted_records = self.deleted.read().await;
        let deleted_credentials = self.deleted_credentials.read().await;

        merged.filter(|record| {
            !Self::record_is_in_deleted_list(record, &deleted_records)
                && !Self::credential_is_in_deleted_list(record, &deleted_credentials)
        })
    }

    fn record_is_in_deleted_list<E>(record: &E, deleted_records: &[EntityId]) -> bool
    where
        E: Entity<ConnectionType = KeystoreDatabaseConnection>,
    {
        let id = EntityId::from_collection_name(E::COLLECTION_NAME, record.id_raw());
        let Ok(id) = id else { return false };
        deleted_records.contains(&id)
    }

    fn credential_is_in_deleted_list<E>(maybe_credential: &E, deleted_credentials: &[Vec<u8>]) -> bool
    where
        E: Entity<ConnectionType = KeystoreDatabaseConnection>,
    {
        let Some(credential) = maybe_credential.downcast::<StoredCredential>() else {
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
///         (identifier_01, StoredCredential),
///         (identifier_02, StoredSignatureKeypair),
///     ],
/// );
///
/// // Commit records of provided types in the first list. Commit records of types in the second
/// // list only if the "proteus-keystore" cargo feature is enabled.
/// commit_transaction!(
///     transaction, db,
///     [
///         (identifier_01, StoredCredential),
///         (identifier_02, StoredSignatureKeypair),
///     ],
///     proteus_types: [
///         (identifier_03, ProteusPrekey),
///         (identifier_04, ProteusIdentity),
///         (identifier_05, ProteusSession)
///     ]
/// );
/// ```
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

            let conn = $db.conn().await?;
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
            StoredCredential::delete_by_credential(&tx, deleted_credential.to_owned()).await?;
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
                (identifier_01, StoredCredential),
                // (identifier_02, StoredSignatureKeypair),
                (identifier_03, StoredHpkePrivateKey),
                (identifier_04, StoredEncryptionKeyPair),
                (identifier_05, StoredEpochEncryptionKeypair),
                (identifier_06, StoredPskBundle),
                (identifier_07, StoredKeypackage),
                (identifier_08, PersistedMlsGroup),
                (identifier_09, PersistedMlsPendingGroup),
                (identifier_10, MlsPendingMessage),
                (identifier_11, StoredE2eiEnrollment),
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
