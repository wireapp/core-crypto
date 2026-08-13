use crate::transaction::Operation;

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
}

impl Operations {
    /// Add an operation to the tail of this list, updating caches appropriately.
    pub(super) fn push(&mut self, operation: Operation) {
        self.operations.push(operation);
    }

    /// Convert the operation at the specified index to a NOP.
    ///
    /// Returns `None` if `idx` is out of bounds, or the displaced operation otherwise.
    pub(super) fn make_nop(&mut self, idx: usize) -> Option<Operation> {
        self.operations
            .get_mut(idx)
            .map(|slot| std::mem::replace(slot, Operation::Nop))
    }
}
