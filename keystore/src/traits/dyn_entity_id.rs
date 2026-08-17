use std::{
    any::Any,
    fmt,
    hash::{Hash, Hasher},
};

/// A dynamic identity type for our entities.
///
/// `EntityId` is mostly sufficient as a table name plus an `Arc<dyn Any>`.
/// But it needs some utility traits in order to accommodate our use cases,
/// and we can't derive or manually implement them on their own precisely because
/// the relevant type has been erased.
///
/// This trait bridges the gap by providing dyn-compatible helpers.
/// There's a blanket impl for every possible valid type.
pub trait DynEntityId: Any + Send + Sync + fmt::Debug {
    /// dyn-compatible hash implementation. Prefer the normal `hash` implemenation where possible.
    //
    // The `Hash` trait is bounded on a `H: Hasher` type parameter.
    // That's not dyn-compatible, so we have to delegate to it with this function.
    fn dyn_hash(&self, state: &mut dyn Hasher);
    /// dyn-compatible equality implementation. Prefer the normal `==` implementation where possible.
    fn dyn_eq(&self, other: &dyn DynEntityId) -> bool;
}

impl<T> DynEntityId for T
where
    T: Any + Send + Sync + fmt::Debug + Hash + Eq,
{
    fn dyn_hash(&self, mut state: &mut dyn Hasher) {
        // the double-`mut` on `state` is not accidental: we need the state itself
        // to be mutable so we can mutably borrow it. We need the mutable reference
        // to satisfy the hasher trait. Deref coersion makes everything line up.
        self.hash(&mut state);
    }

    fn dyn_eq(&self, other: &dyn DynEntityId) -> bool {
        (other as &dyn Any)
            .downcast_ref::<T>()
            .is_some_and(|other| self == other)
    }
}
