use std::collections::HashMap;

use crate::{
    traits::Entity,
    transaction::{Operation, dynamic_dispatch::EntityId, read_outcome::BulkDeleteFilter},
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
#[derive(Default, derive_more::Deref, derive_more::IntoIterator)]
pub(super) struct Operations {
    #[deref]
    #[into_iterator(owned, ref)]
    operations: Vec<Operation>,
    /// indices in the operations list of the most recent upsert operation by entity id
    last_upserts: HashMap<EntityId, usize>,
    /// indices in the operations list of the most recent delete operation by entity id
    last_deletes: HashMap<EntityId, usize>,
    /// indices in the operations list of all bulk deletes by entity table name
    bulk_deletes: HashMap<&'static str, Vec<usize>>,
}

impl Operations {
    /// Add an operation to the tail of this list, updating caches appropriately.
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
    pub(super) fn last_upsert_idx_for(&self, entity_id: &EntityId) -> Option<usize> {
        self.last_upserts.get(entity_id).copied()
    }

    /// Get the index of the last delete for the specified entity id
    pub(super) fn last_delete_idx_for(&self, entity_id: &EntityId) -> Option<usize> {
        self.last_deletes.get(entity_id).copied()
    }

    /// Get the index of the last mutation for the specified entity id
    pub(super) fn last_mutation_idx_for(&self, entity_id: &EntityId) -> Option<usize> {
        let upsert = self.last_upsert_idx_for(entity_id);
        let delete = self.last_delete_idx_for(entity_id);
        upsert.max(delete)
    }

    pub(super) fn upsert_indices_for_type<E>(&self) -> impl '_ + Iterator<Item = usize>
    where
        E: Entity,
    {
        self.last_upserts
            .iter()
            .filter_map(|(entity_id, idx)| entity_id.matches_type::<E>().then_some(*idx))
    }

    pub(super) fn delete_indices_for_type<E>(&self) -> impl '_ + Iterator<Item = usize>
    where
        E: Entity,
    {
        self.last_deletes
            .iter()
            .filter_map(|(entity_id, idx)| entity_id.matches_type::<E>().then_some(*idx))
    }

    /// Returns two lists of equal size: the filters themselves, and the operations indices corresponding to each.
    ///
    /// Having the operations indices enables us to apply only those filters which happened after an operation
    /// to a candidate entity.
    pub(super) fn bulk_delete_filters<E>(&self) -> (Vec<BulkDeleteFilter<E>>, &[usize])
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
                (filters, indices.as_slice())
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
