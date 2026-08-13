//! This module defines a generic operation which can be applied to a database transaction.
//!
//! In general we take advantage of the fact that a closure can be coerced to a bare function
//! pointer, so long as the closure does not actually capture any data. This lets us invent
//! an operation lifecycle like this:
//!
//! - Instantiate with a particular entity as a generic parameter.
//! - Use the information in the generic parameter to expect a particular downcast of the relevant parameter to be
//!   valid.
//! - Produce and store the (type-erased) operation
//! - On application, the contained function pointer knows it was constructed with a particular entity type, and simply
//!   asserts that the downcast succeeds.
//!
//! The type-erasure is important here, because it means that as far as consumers are concerned,
//! an `Operation` is just an opaque type without any type parametrization.

use std::{any::Any, sync::Arc};

use crate::{
    CryptoKeystoreResult,
    traits::{DeletableBySearchKey, Entity, EntityDatabaseMutation, KeyType},
    transaction::dynamic_dispatch::EntityId,
};

/// An operation which can be performed on a transaction.
///
/// When the transaction is committed, the list of operations
/// will be performed in sequence. There is always exactly one
/// order of operations, to ensure that the database always remains consistent.
#[derive(Default, derive_more::Debug, derive_more::IsVariant)]
pub(in crate::transaction) enum Operation {
    /// No operation
    ///
    /// This is a tombstone which is inserted when an operation is reverted,
    /// to ensure that those reversions happen in `O(1)` and not `O(n)`.
    #[default]
    Nop,
    /// An upsert operation.
    ///
    /// This operation updates or inserts an entity into the database.
    Upsert {
        entity_id: EntityId,
        #[debug("Arc<dyn Any + Send + Sync>")]
        entity: Arc<dyn Any + Send + Sync>,
        #[debug(skip)]
        apply: fn(entity: &(dyn Any + Send + Sync), tx: &rusqlite::Transaction<'_>) -> CryptoKeystoreResult<()>,
    },
    /// A delete operation.
    ///
    /// This operation removes an entity from the database.
    Delete {
        entity_id: EntityId,
        #[debug(skip)]
        apply: fn(entity_id: &EntityId, tx: &rusqlite::Transaction<'_>) -> CryptoKeystoreResult<()>,
    },
    /// A bulk delete operation.
    ///
    /// This operation removes multiple entites from the database based on a search key.
    /// It corresponds to [crate::traits::DeletableBySearchKey].
    BulkDelete {
        table_name: &'static str,
        #[debug("Arc<dyn Any + Send + Sync>")]
        search_key: Arc<dyn Any + Send + Sync>,
        #[debug(skip)]
        apply: fn(search_key: &(dyn Any + Send + Sync), tx: &rusqlite::Transaction<'_>) -> CryptoKeystoreResult<()>,
        #[debug(skip)]
        matches: fn(entity: &(dyn Any + Send + Sync), search_key: &(dyn Any + Send + Sync)) -> bool,
    },
}

impl Operation {
    /// Apply this operation to the database.
    pub(in crate::transaction) fn apply(self, tx: &rusqlite::Transaction<'_>) -> CryptoKeystoreResult<()> {
        match self {
            Operation::Nop => Ok(()),
            Operation::Upsert { entity, apply, .. } => (apply)(&*entity, tx),
            Operation::Delete { entity_id, apply } => (apply)(&entity_id, tx),
            Operation::BulkDelete { search_key, apply, .. } => (apply)(&*search_key, tx),
        }
    }

    /// Create an upsert operation.
    pub(in crate::transaction) fn upsert<E>(entity: E) -> Self
    where
        E: 'static + EntityDatabaseMutation + Send + Sync,
    {
        let entity_id = EntityId::from_entity(&entity);
        Self::Upsert {
            entity: Arc::new(entity),
            entity_id,
            apply: |entity, tx| {
                let entity = entity
                    .downcast_ref::<E>()
                    .expect("this type is set when we create the operation and cannot be wrong");
                entity.save(tx)
            },
        }
    }

    /// Create a delete operation.
    pub(in crate::transaction) fn delete<E>(entity_id: EntityId) -> Self
    where
        E: EntityDatabaseMutation,
    {
        debug_assert!(
            entity_id.matches_type::<E>(),
            "correct code will always provide an entity id of the proper type"
        );
        Self::Delete {
            entity_id,
            apply: |entity_id, tx| {
                let id = entity_id.primary_key::<E>()?;
                E::delete(tx, &id).map(|_| ())
            },
        }
    }

    /// Create a bulk delete operation.
    pub(in crate::transaction) fn bulk_delete<E, S>(search_key: S) -> Self
    where
        E: 'static + EntityDatabaseMutation + DeletableBySearchKey<S>,
        S: 'static + KeyType,
    {
        Self::BulkDelete {
            table_name: E::TABLE_NAME,
            search_key: Arc::new(search_key),
            apply: |search_key, tx| {
                let search_key = search_key
                    .downcast_ref::<S>()
                    .expect("this type is set when we create the operation and cannot be wrong");
                E::delete_all_matching(tx, search_key)
            },
            matches: |entity, search_key| {
                let Some(entity) = entity.downcast_ref::<E>() else {
                    return false;
                };
                let Some(search_key) = search_key.downcast_ref::<S>() else {
                    return false;
                };

                entity.matches(search_key)
            },
        }
    }

    /// Gets the entity ID associated with this operation.
    ///
    /// This returns an entity ID only if this operation is an insert or delete.
    pub(in crate::transaction) fn entity_id(&self) -> Option<&EntityId> {
        match self {
            Operation::Upsert { entity_id, .. } | Operation::Delete { entity_id, .. } => Some(entity_id),
            Operation::BulkDelete { .. } | Operation::Nop => None,
        }
    }

    /// `Some(e)` when this operation is an upsert for `E`
    pub(in crate::transaction) fn as_upsert<E>(&self) -> Option<Arc<E>>
    where
        E: 'static + Send + Sync,
    {
        let Self::Upsert { entity, .. } = self else {
            return None;
        };
        entity.clone().downcast().ok()
    }

    /// `Some(entity_id)` when this operation is a delete for that id
    pub(in crate::transaction) fn as_delete<E>(&self) -> Option<EntityId>
    where
        E: Entity,
    {
        let Self::Delete { entity_id, .. } = self else {
            return None;
        };
        entity_id.matches_type::<E>().then(|| entity_id.clone())
    }

    /// `Some(should_delete(entity))` when this operation is a bulk deletion
    ///
    /// The return type here uses somewhat unusual syntax, but its meaning is simple:
    /// `use<E>` means the only generic parameter of the returned function is `E`;
    /// the returned function does _not_ have a lifetime tied to the lifetime of `&self`.
    pub(in crate::transaction) fn as_bulk_delete_filter<E>(&self) -> Option<impl use<E> + Fn(&E) -> bool + Send + Sync>
    where
        E: 'static + Send + Sync,
    {
        let Self::BulkDelete {
            search_key, matches, ..
        } = self
        else {
            return None;
        };

        // clone the Arc'd search key; cheap
        let search_key = search_key.clone();
        // deref the (borrowed) function pointer so the closure can own it; cheap
        let matches = *matches;

        Some(move |entity: &E| matches(entity, &*search_key))
    }

    /// `Some(table_name)` when this operation is a bulk deletion
    pub(in crate::transaction) fn as_bulk_delete_table_name(&self) -> Option<&'static str> {
        match self {
            Self::BulkDelete { table_name, .. } => Some(table_name),
            _ => None,
        }
    }
}
