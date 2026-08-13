use std::collections::HashMap;

use crate::{
    traits::Entity,
    transaction::{Operation, dynamic_dispatch::EntityId},
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
    last_deletes: HashMap<EntityId, usize>,
}

impl Operations {
    /// Add an operation to the tail of this list, updating caches appropriately.
    pub(super) fn push(&mut self, operation: Operation) {
        if let Some(entity_id) = operation.entity_id()
            && operation.is_delete()
        {
            self.last_deletes.insert(entity_id.clone(), self.operations.len());
        }
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

        // ensure we update the last delete table for this entity
        // if we just nop'd the last delete
        if let Some(displaced) = displaced.as_ref()
            && let Some(entity_id) = displaced.entity_id()
            && displaced.is_delete()
            && idx == self.last_deletes[entity_id]
        {
            // we have to scan here, but not from the end; only leftwards from the old position
            let new_final_position = self.operations[..idx].iter().rposition(|operation| {
                operation.is_delete()
                    && operation
                        .entity_id()
                        .is_some_and(|op_entity_id| op_entity_id == entity_id)
            });

            match new_final_position {
                Some(position) => {
                    let cached_position = self
                        .last_deletes
                        .get_mut(entity_id)
                        .expect("last modification already exists because there exists a displaced operation");
                    *cached_position = position;
                }
                None => {
                    self.last_deletes.remove(entity_id);
                }
            }
        }

        displaced
    }

    /// Get the index of the last delete for the specified entity id
    pub(super) fn last_delete_idx_for(&self, entity_id: &EntityId) -> Option<usize> {
        self.last_deletes.get(entity_id).copied()
    }

    pub(super) fn delete_indices_for_type<E>(&self) -> impl '_ + Iterator<Item = usize>
    where
        E: Entity,
    {
        self.last_deletes
            .iter()
            .filter_map(|(entity_id, idx)| entity_id.matches_type::<E>().then_some(*idx))
    }
}
