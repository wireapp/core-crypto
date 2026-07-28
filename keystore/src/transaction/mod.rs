mod entity_read;
mod entity_write;
mod fetch_from_database;
mod specializations;

use std::{borrow::Cow, collections::HashSet, sync::Arc};

use async_lock::{RwLock, SemaphoreGuardArc};
use itertools::Itertools;
use ordermap::OrderMap;

use crate::{
    CryptoKeystoreError, CryptoKeystoreResult, Database, UniqueArc,
    traits::{Entity, KeyType},
    transaction::dynamic_dispatch::EntityId,
};

pub(crate) mod dynamic_dispatch;

/// This represents a transaction, where all operations will be done in memory and committed at the
/// end
#[derive(Debug)]
pub struct KeystoreTransaction {
    cache: RwLock<OrderMap<EntityId, dynamic_dispatch::Entity>>,
    deleted: RwLock<HashSet<EntityId>>,
    _semaphore_guard: Arc<SemaphoreGuardArc>,
    database: Arc<Database>,
}

impl KeystoreTransaction {
    /// Instantiate a new transaction.
    ///
    /// Requires a semaphore guard to ensure that only one exists at a time.
    pub(crate) async fn new(
        semaphore_guard: SemaphoreGuardArc,
        database: Arc<Database>,
    ) -> CryptoKeystoreResult<UniqueArc<Self>> {
        let transaction = UniqueArc::from(Self {
            cache: Default::default(),
            deleted: Default::default(),
            _semaphore_guard: Arc::new(semaphore_guard),
            database,
        });

        let weak = UniqueArc::downgrade(&transaction);

        {
            let mut transaction_guard = transaction.database.transaction.lock().await;
            // this transaction guard may be `None` if the database is new or the previous transaction
            // was committed.
            // it may be `Some(_)` if the previous transaction was rolled back by means of dropping the `UniqueArc<Transaction>`.
            // either way, it's correct to simply replace it without checking the previous value.
            *transaction_guard = Some(weak);
        }

        Ok(transaction)
    }

    /// Build a single list of unique records from two potentially overlapping lists.
    /// In case of overlap, records in `records_a` are prioritized.
    /// Identity from the perspective of this function is determined by the output of
    /// [Entity::merge_key].
    ///
    /// Further, the output list of records is built with respect to the provided [EntityFindParams]
    /// and the deleted records cached in this [Self] instance.
    async fn merge_records<'a, E>(
        &self,
        records_a: impl IntoIterator<Item = Cow<'a, E>>,
        records_b: impl IntoIterator<Item = Cow<'a, E>>,
    ) -> Vec<E>
    where
        E: 'static + Clone + Entity,
    {
        let deleted_records = self.deleted.read().await;

        records_a
            .into_iter()
            .chain(records_b)
            .unique_by(|e| e.primary_key().bytes().into_owned())
            .filter_map(|record| {
                let id = EntityId::from_entity(record.as_ref())?;
                (!deleted_records.contains(&id)).then_some(record.into_owned())
            })
            .collect()
    }
}

impl UniqueArc<KeystoreTransaction> {
    /// Persists all the operations in the database. It will effectively open a transaction
    /// internally, perform all the buffered operations and commit.
    pub async fn commit(self) -> Result<(), CryptoKeystoreError> {
        let KeystoreTransaction {
            cache,
            deleted,
            database,
            ..
        } = UniqueArc::into_inner(self).await;
        let cache = cache.into_inner();
        let deleted_ids = deleted.into_inner();

        if cache.is_empty() && deleted_ids.is_empty() {
            log::debug!("Empty transaction was committed.");
            return Ok(());
        }

        // open a database transaction
        // Because `rusqlite::Transaction: !Send + !Sync`, it's critical that
        // we don't hold this transaction over any `.await` points.
        let mut conn = database.conn().await;
        let tx = conn.transaction()?;

        for entity in cache.values() {
            entity.execute_save(&tx)?;
        }

        for deleted_id in deleted_ids.iter() {
            deleted_id.execute_delete(&tx)?;
        }

        // and commit everything
        tx.commit()?;

        Ok(())
    }
}
