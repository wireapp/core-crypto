use core::fmt;
use std::{any::Any, hash::Hash, sync::Arc};

use crate::traits::{BorrowPrimaryKey, DynEntityId, Entity};

/// Identifies one database record: which table it lives in, plus its primary key within that table.
///
/// This is the type-erased counterpart to an [`Entity`]'s primary key. Equality and hashing cover
/// both fields, so two entities of different types never collide even if their key bytes agree, and
/// an id built from a borrowed key compares equal to one built from the owned form.
///
/// ## Invariant
///
/// [`Entity::TABLE_NAME`] has to identify the Rust type uniquely. This type only ever compares table
/// names (`Self::matches_type`), while the operations which act on the entity behind an id recover
/// the type by downcasting, so the two notions of identity have to agree. Were two entity types ever
/// to share a table name, `matches_type` would answer `true` for both while the downcast succeeded
/// for only one — turning the `expect`s which pair the two into panics, and making bulk deletions
/// silently match nothing. Adding an entity therefore means giving it a table name no other entity
/// uses.
#[derive(Debug, Clone)]
pub struct EntityId {
    /// the table this record lives in, which also identifies its Rust type
    table_name: &'static str,
    /// the record's primary key
    key: Arc<dyn DynEntityId>,
}

impl fmt::Display for EntityId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Self { table_name, key } = self;
        write!(f, "{table_name}: {key:?}")
    }
}

impl PartialEq for EntityId {
    fn eq(&self, other: &Self) -> bool {
        self.table_name == other.table_name && self.key.dyn_eq(&*other.key)
    }
}

impl Eq for EntityId {}

impl Hash for EntityId {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.table_name.hash(state);
        self.key.dyn_hash(state);
    }
}

impl EntityId {
    /// `true` when this id refers to a record of type `E`
    ///
    /// This is a table name comparison, which stands in for a type comparison by the invariant
    /// documented on [`EntityId`].
    pub(crate) fn matches_type<E>(&self) -> bool
    where
        E: Entity,
    {
        self.table_name == E::TABLE_NAME
    }

    /// Recover the typed primary key from this id.
    ///
    /// Produces `None` if this id is of the wrong type for `E`.
    pub(crate) fn primary_key<E>(&self) -> Option<Arc<E::PrimaryKey>>
    where
        E: Entity,
    {
        // multiple entities might have the same primary key type, so downcasting alone
        // isn't sufficient to ensure that this is actually a key for the requested entity type
        self.matches_type::<E>()
            .then(|| (self.key.clone() as Arc<dyn Any + Send + Sync>).downcast().ok())
            .flatten()
    }

    /// Build the id of the record of type `E` with this primary key.
    ///
    /// The other constructors all funnel through here.
    pub fn from_primary_key<E>(primary_key: E::PrimaryKey) -> Self
    where
        E: Entity,
    {
        Self {
            table_name: E::TABLE_NAME,
            key: Arc::new(primary_key) as _,
        }
    }

    /// Build the id of an entity instance.
    ///
    /// Note that this asks the entity for its primary key, which for some entities means hashing
    /// their contents. Where the id is already available — as a cache key, say — reuse it rather than
    /// deriving it again.
    pub fn from_entity<E>(entity: &E) -> Self
    where
        E: Entity,
    {
        Self::from_primary_key::<E>(entity.primary_key())
    }

    /// Build the id of the record of type `E` with this primary key, in its borrowed form.
    ///
    /// Equal to what [`Self::from_primary_key`] produces for the owned form of the same key, so the
    /// two are interchangeable for lookups.
    pub fn from_borrowed_primary_key<E>(primary_key: &E::BorrowedPrimaryKey<'_>) -> Self
    where
        E: Entity + BorrowPrimaryKey,
    {
        Self::from_primary_key::<E>((*primary_key).into())
    }
}
