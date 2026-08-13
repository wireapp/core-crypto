/// A filter function which can be used to omit entities returned from the database from a transaction query.
///
/// Each bulk delete excludes certain entities, but due to the types and traits in play,
/// we can't tell whether it applies to a given entity without having an instance
/// in hand.
pub(crate) type BulkDeleteFilter<E> = Box<dyn Fn(&E) -> bool + Send + Sync>;

/// Bulk delete filters apply only on or afer a particular operation.
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
    pub(super) fn applies_after(&self, entity: &E, idx: usize) -> bool {
        self.filters
            .iter()
            .zip(self.filter_indices)
            .skip_while(|(_filter, filter_idx)| **filter_idx < idx)
            .any(|(filter, _idx)| filter(entity))
    }

    /// Extract the filters, discarding the filter indices
    pub(super) fn into_inner(self) -> Vec<BulkDeleteFilter<E>> {
        self.filters
    }
}
