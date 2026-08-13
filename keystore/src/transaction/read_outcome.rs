use std::sync::Arc;

use crate::transaction::BulkDeleteFilter;

/// The outcome of a read operation on a transaction
///
/// Transactions record not just individual entity upsert and delete operations, but also
/// bulk deletions. A read outcome therefore includes information not just about the entity requested,
/// but filters which can be used to exclude other entities produced by the database.
///
/// NOTE: it is possible for this function to have both `entity: Some(Some(e))` and `outcome.should_omit(e)`.
/// This just indicates that a bulk deletion covered `e`, but then it was re-upserted afterwards.
pub(crate) struct ReadOutcome<E> {
    /// The outcome of this read operation as applied to the operations of this transaction:
    ///
    /// * `Some(Some(E))` - the transaction cache contains the record
    /// * `Some(None)` - the deletion of the record has been cached
    /// * `None` - there is no information about the record in the cache
    pub(crate) entity: Option<Option<Arc<E>>>,
    /// Each bulk delete operation produces a filter which must be applied to instances from the DB.
    ///
    /// If any function in this list returns `true` for an entity instance, then that entity has been
    /// affected by a bulk deletion and should be omitted from result lists.
    pub(crate) filters: Vec<BulkDeleteFilter<E>>,
}

impl<E> ReadOutcome<E> {
    /// Helper function to apply all the filters to an entity instance.
    ///
    /// If this returns `true` then the entity should be omitted from results.
    pub(crate) fn should_omit(&self, entity: &E) -> bool {
        self.filters.iter().any(|filter| (filter)(entity))
    }
}

// manually derived to avoid undesired `E: Default` bound
impl<E> Default for ReadOutcome<E> {
    fn default() -> Self {
        Self {
            entity: Default::default(),
            filters: Default::default(),
        }
    }
}
