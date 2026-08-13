/// A filter function which can be used to omit entities returned from the database from a transaction query.
///
/// Each bulk delete excludes certain entities, but due to the types and traits in play,
/// we can't tell whether it applies to a given entity without having an instance
/// in hand.
pub(crate) type BulkDeleteFilter<E> = Box<dyn Fn(&E) -> bool + Send + Sync>;

/// The bulk deletions affecting one entity type, each paired with the operation index at which it happened.
///
/// A bulk deletion buries an entity only if it came *after* the operation which produced that
/// entity: clearing a conversation and then buffering a new message for it must leave the new
/// message alone. Knowing which filters match an entity is therefore not enough on its own; we also
/// have to know where each one sat in the operations list. Hence the indices.
///
/// The two fields are parallel: `filters[i]` belongs to the bulk delete at operation index
/// `filter_indices[i]`, and `filter_indices` is ascending. [`Self::applies_after`] relies on both
/// properties. Nothing in this type enforces them, so [`Operations::bulk_delete_filters`] — which
/// derives the filters from the indices it is handed — should remain the only place which constructs
/// one.
///
/// [`Operations::bulk_delete_filters`]: crate::transaction::operations::Operations::bulk_delete_filters
#[derive(derive_more::Constructor)]
pub(super) struct BulkDeleteFilters<'a, E> {
    filters: Vec<BulkDeleteFilter<E>>,
    filter_indices: &'a [usize],
}

impl<'a, E> Default for BulkDeleteFilters<'a, E> {
    fn default() -> Self {
        Self {
            filters: Default::default(),
            filter_indices: Default::default(),
        }
    }
}

impl<'a, E> BulkDeleteFilters<'a, E> {
    /// `true` when a filter was added after the operation index `idx` which indicates to omit the provided entity
    ///
    /// Pass the index of the operation which produced `entity`. Bulk deletions before that point
    /// removed whatever was in the table at the time; they say nothing about an entity written
    /// afterwards, so they must not be consulted.
    ///
    /// Strictly the comparison is "at or after `idx`", but no two operations share an index, so a
    /// filter can never sit at the same index as the operation which produced the entity.
    pub(super) fn applies_after(&self, entity: &E, idx: usize) -> bool {
        self.filters
            .iter()
            .zip(self.filter_indices)
            .skip_while(|(_filter, filter_idx)| **filter_idx < idx)
            .any(|(filter, _idx)| filter(entity))
    }

    /// Extract the filters, discarding the filter indices
    ///
    /// Dropping the indices is only sound for entities which predate every operation in this
    /// transaction, which in practice means records loaded from the database. Every bulk deletion in
    /// the list necessarily comes after such a record, so there is nothing left for an index to
    /// decide. An entity which came out of the transaction cache has a position of its own and must
    /// go through [`Self::applies_after`] instead.
    pub(super) fn into_inner(self) -> Vec<BulkDeleteFilter<E>> {
        self.filters
    }
}
