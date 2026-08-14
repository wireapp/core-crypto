mod bulk_delete_filter;
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

use std::{collections::HashMap, sync::Arc};

use async_lock::{RwLock, SemaphoreGuardArc};
use rusqlite::TransactionBehavior;

pub(crate) use self::{bulk_delete_filter::BulkDeleteFilter, read_outcome::ReadOutcome};
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
    ///
    /// Note that the position of each deletion within the transaction is not consulted here, unlike
    /// in the cache-only reads. Every record in `from_database` predates the whole transaction, so any
    /// deletion in it applies; and "unless later re-added" needs no ordering either, because a
    /// re-added entity arrives through `from_tx_cache`, which is applied afterwards and therefore
    /// wins. That leaves the two sources responsible for different halves of the answer:
    /// `from_tx_cache` is expected to have resolved ordering among the operations already, which is
    /// what [`Self::find_all_in_cache`] does for it.
    ///
    /// The returned order is unspecified, as the merge runs through a `HashMap`.
    async fn merge_records<E>(
        &self,
        from_tx_cache: impl IntoIterator<Item = Arc<E>>,
        from_database: impl IntoIterator<Item = Arc<E>>,
    ) -> impl Iterator<Item = Arc<E>>
    where
        E: 'static + Clone + Entity + Send + Sync,
    {
        let mut cache = {
            let operations = self.operations.read().await;
            let filters = operations.bulk_delete_filters();

            // construct the cache from the database's items,
            // filtering out those items which have been deleted individually or in bulk
            from_database
                .into_iter()
                .filter_map(|entity| {
                    let entity_id = EntityId::from_entity(&*entity);

                    // the delete may have been overwritten by a later upsert, true,
                    // but in that case we lose nothing by deleting here, because we
                    // are still about to upsert a few lines from now
                    //
                    // bulk-deletes apply to the database entities regardless of when they happen
                    let excluded =
                        operations.last_delete_idx_for(&entity_id).is_some() || filters.applies_after(&*entity, 0);
                    (!excluded).then_some((entity_id, entity))
                })
                .collect::<HashMap<_, _>>()
        };

        // update with everything which was inserted by the tx cache
        for entity in from_tx_cache {
            let id = EntityId::from_entity(&*entity);
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
