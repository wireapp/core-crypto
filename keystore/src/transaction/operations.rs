use std::collections::HashMap;

use crate::{
    traits::Entity,
    transaction::{Operation, bulk_delete_filter::BulkDeleteFilters, dynamic_dispatch::EntityId},
};

/// A list of operations with some caches intended to ease traversal of that list.
///
/// These are all logically grouped together: if we want to be able to read from
/// one of these things, we want to read all of them. If we want to be able to
/// write one, we want to be able to write all. So we group them together in this
/// struct so they can all live under a single lock in the transaction.
///
/// While this doesn't implement all of the `Vec<Operation>` interface, it does
/// implement `Deref`, `IntoIterator`, and `.push`, so it covers the basic use
/// cases transparently.
///
/// ## Invariants
///
/// The caches are only correct as long as every mutation of the operations list goes through
/// [`Self::push`] or [`Self::make_nop`]. That is what the `Deref` impl is for: it hands out
/// `&Vec<Operation>`, so callers get the entire read-only `Vec` API and no way to append, remove,
/// or reorder behind the caches' back. A `DerefMut` impl, or any other method which touches
/// `operations` without maintaining the tables alongside it, would silently break every reader.
///
/// Every cached `usize` is an index into `operations`. That list is only ever appended to, and
/// entries within it are only ever replaced in place by [`Operation::Nop`], so an index stays valid
/// for the life of the transaction and comparing two of them tells you which operation came first.
/// Several readers depend on exactly that: "was this entity deleted after it was upserted" is
/// answered by comparing two cached indices.
#[derive(Default, derive_more::Deref, derive_more::IntoIterator)]
pub(super) struct Operations {
    #[deref]
    #[into_iterator(owned, ref)]
    operations: Vec<Operation>,
    /// index in the operations list of the *most recent* upsert of each entity id
    ///
    /// Only the most recent one: earlier upserts of the same entity id are not reachable from here.
    last_upserts: HashMap<EntityId, usize>,
    /// index in the operations list of the *most recent* delete of each entity id
    ///
    /// Only the most recent one: earlier deletes of the same entity id are not reachable from here.
    last_deletes: HashMap<EntityId, usize>,
    /// indices in the operations list of *every* bulk delete, grouped by the table it targets
    ///
    /// Unlike the two tables above, this keeps all of them, because a bulk delete is defined by a
    /// search key instead of an entity id: there is no way to know whether a later one subsumes an
    /// earlier one without an entity instance in hand. Each list is ascending, because
    /// [`Self::push`] only appends and [`Self::make_nop`] only removes; readers rely on that
    /// ordering to skip past deletions which predate the operation they care about.
    bulk_deletes: HashMap<&'static str, Vec<usize>>,
}

impl Operations {
    /// Add an operation to the tail of this list, updating caches appropriately.
    ///
    /// An [`Operation::Nop`] is discarded instead of stored: it would do nothing on commit and
    /// nothing for any reader, so the only Nops which ever appear in the list are the tombstones
    /// [`Self::make_nop`] leaves behind.
    pub(super) fn push(&mut self, operation: Operation) {
        match &operation {
            Operation::Nop => {
                // why bother?
                return;
            }
            Operation::Upsert { entity_id, .. } => {
                self.last_upserts.insert(entity_id.clone(), self.operations.len());
            }
            Operation::Delete { entity_id, .. } => {
                self.last_deletes.insert(entity_id.clone(), self.operations.len());
            }
            Operation::BulkDelete { table_name, .. } => self
                .bulk_deletes
                .entry(table_name)
                .or_default()
                .push(self.operations.len()),
        }

        // store the actual operation
        self.operations.push(operation);
    }

    /// Convert the operation at the specified index to a NOP.
    ///
    /// Returns `None` if `idx` is out of bounds, or the displaced operation otherwise.
    ///
    /// Replacing in place rather than removing is what keeps every other cached index valid; see the
    /// invariants on [`Operations`].
    ///
    /// If the displaced operation was the most recent of its kind for its entity id, that cache entry
    /// has to move to the next most recent operation of the same kind, or disappear if there is none.
    /// Finding that predecessor is the only place in this type which scans the operations list, and
    /// even then only leftwards from `idx`.
    pub(super) fn make_nop(&mut self, idx: usize) -> Option<Operation> {
        let displaced = self
            .operations
            .get_mut(idx)
            .map(|operation| std::mem::replace(operation, Operation::Nop));

        // ensure we update the mutation tables for this entity
        // if we just nop'd the last relevant mutation
        if let Some(displaced) = displaced.as_ref() {
            let scan_params = match displaced {
                Operation::Nop => None,
                Operation::BulkDelete { table_name, .. } => {
                    self.bulk_deletes
                        .get_mut(table_name)
                        .expect("we displaced a bulk delete so its entry must exist")
                        .retain(|delete_idx| *delete_idx != idx);
                    None
                }
                Operation::Upsert { entity_id, .. } => (idx == self.last_upserts[entity_id]).then_some((
                    &mut self.last_upserts,
                    (|operation: &Operation| operation.is_upsert()) as fn(&Operation) -> bool,
                    entity_id,
                )),
                Operation::Delete { entity_id, .. } => (idx == self.last_deletes[entity_id]).then_some((
                    &mut self.last_deletes,
                    (|operation: &Operation| operation.is_delete()) as _,
                    entity_id,
                )),
            };

            // scan_params are set on mutations where we have to scan to find the new relevant parameter, or remove
            // that entity id from the table entirely if there are no more mutations of that kind.
            if let Some((table, is_relevant, entity_id)) = scan_params {
                // we have to scan here, but not from the end; only leftwards from the old position
                let new_final_position = self.operations[..idx].iter().rposition(|operation| {
                    is_relevant(operation)
                        && operation
                            .entity_id()
                            .is_some_and(|op_entity_id| op_entity_id == entity_id)
                });

                match new_final_position {
                    Some(position) => {
                        let cached_position = table
                            .get_mut(entity_id)
                            .expect("last modification already exists because there exists a displaced operation");
                        *cached_position = position;
                    }
                    None => {
                        table.remove(entity_id);
                    }
                }
            }
        }

        displaced
    }

    /// Get the index of the last upsert for the specified entity id
    ///
    /// `None` when this transaction has not upserted that entity at all. Note that an upsert being
    /// the last one does not make it live: a later delete or bulk delete may have buried it.
    pub(super) fn last_upsert_idx_for(&self, entity_id: &EntityId) -> Option<usize> {
        self.last_upserts.get(entity_id).copied()
    }

    /// Get the index of the last delete for the specified entity id
    ///
    /// `None` when this transaction has not deleted that entity at all. Note that a delete being the
    /// last one does not make the entity gone: a later upsert may have restored it, which is why
    /// callers who care about the entity's current state compare this against
    /// [`Self::last_upsert_idx_for`] rather than treating a hit here as final.
    pub(super) fn last_delete_idx_for(&self, entity_id: &EntityId) -> Option<usize> {
        self.last_deletes.get(entity_id).copied()
    }

    /// Get the index of the last mutation for the specified entity id
    ///
    /// A mutation here is an upsert or a delete. Bulk deletes are keyed by search key rather than by
    /// entity id, so they are not mutations in this sense and are not considered.
    ///
    /// Taking the maximum works because both candidates index the same append-only list, so the
    /// larger index is the later operation. It also does the right thing when only one of the two
    /// kinds exists, because `None` sorts below every `Some`.
    pub(super) fn last_mutation_idx_for(&self, entity_id: &EntityId) -> Option<usize> {
        let upsert = self.last_upsert_idx_for(entity_id);
        let delete = self.last_delete_idx_for(entity_id);
        upsert.max(delete)
    }

    /// The most recent upsert of each entity of type `E`, as `(entity id, operation index)`
    ///
    /// This yields one item per entity id, *not* one per upsert: earlier upserts of the same entity
    /// are not reachable through it. Nor is an item necessarily live, since a later delete or bulk
    /// delete may have buried it, so callers wanting the transaction's current state have to check
    /// for that themselves.
    ///
    /// Iteration order is unspecified; this walks a `HashMap`.
    pub(super) fn upsert_indices_for_type<E>(&self) -> impl '_ + Iterator<Item = (&EntityId, usize)>
    where
        E: Entity,
    {
        self.last_upserts
            .iter()
            .filter_map(|(entity_id, idx)| entity_id.matches_type::<E>().then_some((entity_id, *idx)))
    }

    /// The index of the most recent delete of each entity of type `E`
    ///
    /// As with [`Self::upsert_indices_for_type`], this yields one item per entity id rather than one
    /// per delete, and an item is not necessarily the entity's current state: a later upsert may
    /// have restored it.
    ///
    /// Iteration order is unspecified; this walks a `HashMap`.
    pub(super) fn delete_indices_for_type<E>(&self) -> impl '_ + Iterator<Item = usize>
    where
        E: Entity,
    {
        self.last_deletes
            .iter()
            .filter_map(|(entity_id, idx)| entity_id.matches_type::<E>().then_some(*idx))
    }

    /// Every bulk delete affecting type `E`, each paired with the operation index at which it happened.
    ///
    /// The indices are what let a caller apply only those deletions which came after some particular
    /// operation, which is what an entity taken from the transaction cache needs; see
    /// [`BulkDeleteFilters::applies_after`].
    pub(super) fn bulk_delete_filters<E>(&self) -> BulkDeleteFilters<'_, E>
    where
        E: 'static + Entity + Send + Sync,
    {
        self.bulk_deletes
            .get(E::TABLE_NAME)
            .map(|indices| {
                let filters = indices
                    .iter()
                    .copied()
                    .map(|idx| {
                        let filter = self.operations[idx]
                            .as_bulk_delete_filter()
                            .expect("bulk delete indices must point to bulk delete operation");
                        Box::new(filter) as _
                    })
                    .collect();
                BulkDeleteFilters::new(filters, indices)
            })
            .unwrap_or_default()
    }

    /// True if the operations list contains no non-Nop operations.
    ///
    /// This intentionally shadows Vec::is_empty
    pub(super) fn is_empty(&self) -> bool {
        // https://doc.rust-lang.org/stable/std/iter/trait.Iterator.html#method.all
        // > An empty iterator returns `true`.
        self.operations
            .iter()
            .all(|operation| matches!(operation, Operation::Nop))
    }
}
