mod dynamic_dispatch;
mod entity_read;
mod entity_write;
mod fetch_from_database;
mod mls;
mod operations;
#[cfg(feature = "proteus-keystore")]
pub mod proteus;
mod read_outcome;
mod specializations;

use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};

use async_lock::{RwLock, SemaphoreGuardArc};
use rusqlite::TransactionBehavior;

pub(crate) use self::read_outcome::ReadOutcome;
use crate::{
    CryptoKeystoreError, CryptoKeystoreResult, Database, UniqueArc,
    traits::Entity,
    transaction::{
        dynamic_dispatch::{EntityId, Operation},
        operations::Operations,
    },
};

/// This is an in-flight transaction: all operations are buffered in memory, and only
/// applied to the database on [`commit`][UniqueArc<Self>::commit].
///
/// Dropping the transaction without committing performs an implicit rollback.
///
/// This type is always wrapped in a [`UniqueArc`], which keeps things efficient,
/// at the cost of prohibiting `Clone`. In case you need to share this around,
/// there are weak references available via [`UniqueArc::downgrade`].
/// Alternately, wrap the entire thing in an `Arc<Mutex<Option<UniqueArc<Self>>>>` or similar.
/// Just be aware that you'll need to take the unique arc out in order to commit.
pub struct Transaction {
    operations: RwLock<Operations>,
    _semaphore_guard: SemaphoreGuardArc,
    database: Arc<Database>,
}

impl Transaction {
    /// Instantiate a new transaction.
    ///
    /// Requires a semaphore guard to ensure that only one exists at a time.
    pub(crate) async fn new(
        semaphore_guard: SemaphoreGuardArc,
        database: Arc<Database>,
    ) -> CryptoKeystoreResult<UniqueArc<Self>> {
        let transaction = UniqueArc::from(Self {
            operations: Default::default(),
            _semaphore_guard: semaphore_guard,
            database,
        });

        let weak = UniqueArc::downgrade(&transaction);

        {
            let mut transaction_guard = transaction.database.transaction.lock().await;
            // this transaction guard may be `None` if the database is new or the previous transaction
            // was committed.
            // it may be `Some(_)` if the previous transaction was rolled back by means of dropping the
            // `UniqueArc<Transaction>`. either way, it's correct to simply replace it without checking the
            // previous value.
            *transaction_guard = Some(weak);
        }

        Ok(transaction)
    }

    /// Merge the database's view of entity records with entities from the transaction cache.
    ///
    /// Entities deleted singly or in bulk from the operations list are excluded, unless later re-added.
    ///
    /// Entities upserted in the tx cache overwrite entities from the database.
    async fn merge_records<E>(
        &self,
        from_tx_cache: impl IntoIterator<Item = E>,
        from_database: impl IntoIterator<Item = E>,
    ) -> impl Iterator<Item = E>
    where
        E: 'static + Clone + Entity + Send + Sync,
    {
        let (deleted_ids, filters) = {
            let operations = self.operations.read().await;
            let deleted_ids = operations
                .delete_indices_for_type::<E>()
                .map(|idx| {
                    operations[idx]
                        .as_delete::<E>()
                        .expect("delete_indices_for_type produces correct indices")
                })
                .collect::<HashSet<_>>();

            let (filters, _) = operations.bulk_delete_filters();
            (deleted_ids, filters)
        };

        // construct the cache from the database's items,
        // filtering out those items which have been deleted individually or in bulk
        let mut cache = from_database
            .into_iter()
            .filter_map(|e| {
                let entity_id = EntityId::from_entity(&e);
                let excluded = deleted_ids.contains(&entity_id) || filters.iter().any(|filter| filter(&e));
                (!excluded).then_some((entity_id, e))
            })
            .collect::<HashMap<_, _>>();

        // update with everything which was inserted by the tx cache
        for entity in from_tx_cache {
            let id = EntityId::from_entity(&entity);
            cache.insert(id, entity);
        }

        cache.into_values()
    }
}

impl UniqueArc<Transaction> {
    /// Persists all the operations in the database. It will effectively open a transaction
    /// internally, perform all the buffered operations and commit.
    pub async fn commit(self) -> Result<(), CryptoKeystoreError> {
        let Transaction {
            operations,
            database,
            _semaphore_guard,
        } = UniqueArc::into_inner(self).await;
        let operations = operations.into_inner();

        // clear the weak reference to this transaction
        *database.transaction.lock().await = None;

        if operations.is_empty() {
            log::debug!("Empty transaction was committed.");
            return Ok(());
        }

        // open a database transaction
        // Because `rusqlite::Transaction: !Send + !Sync`, it's critical that
        // we don't hold this transaction over any `.await` points.
        let mut conn = database.conn().await;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;

        for operation in operations {
            operation.apply(&tx)?;
        }

        // and commit everything
        tx.commit()?;

        Ok(())
    }
}
