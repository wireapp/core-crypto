use core::fmt;
use std::borrow::Cow;

use crate::{
    CryptoKeystoreError, CryptoKeystoreResult,
    traits::{BorrowPrimaryKey, Entity, KeyType, OwnedKeyType as _},
};

/// Identifies one database record: which table it lives in, plus its primary key within that table.
///
/// This is the type-erased counterpart to an [`Entity`]'s primary key. Equality and hashing cover
/// both fields, so two entities of different types never collide even if their key bytes agree, and
/// an id built from a borrowed key compares equal to one built from the owned form.
///
/// ## Invariant
///
/// [`Entity::TABLE_NAME`] has to identify the Rust type uniquely. This type only ever compares table
/// names ([`Self::matches_type`]), while the operations which act on the entity behind an id recover
/// the type by downcasting, so the two notions of identity have to agree. Were two entity types ever
/// to share a table name, `matches_type` would answer `true` for both while the downcast succeeded
/// for only one — turning the `expect`s which pair the two into panics, and making bulk deletions
/// silently match nothing. Adding an entity therefore means giving it a table name no other entity
/// uses.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct EntityId {
    /// the table this record lives in, which also identifies its Rust type
    table_name: &'static str,
    /// the record's primary key, in the byte encoding given by [`KeyType::bytes`]
    id: Vec<u8>,
}

impl fmt::Display for EntityId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Self { table_name, id } = self;
        write!(f, "{table_name:?}: {}", hex::encode(id))
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
    /// Errors with [`CryptoKeystoreError::InvalidPrimaryKeyBytes`] if the stored bytes are not a valid
    /// encoding of `E::PrimaryKey`, which for an id built by one of the constructors below can only
    /// happen if `E` is the wrong type.
    pub(crate) fn primary_key<E>(&self) -> CryptoKeystoreResult<E::PrimaryKey>
    where
        E: Entity,
    {
        // we'd prefer not to pay the cost for a runtime check, but we want more than 0 checks
        debug_assert!(
            self.matches_type::<E>(),
            "well-constructed code will never call this for a non-matching type"
        );
        E::PrimaryKey::from_bytes(&self.id).ok_or(CryptoKeystoreError::InvalidPrimaryKeyBytes(self.table_name))
    }

    /// Build an id for a record of type `E` from the byte encoding of its primary key.
    ///
    /// The other constructors all funnel through here; prefer them where one fits, as they derive the
    /// encoding rather than trusting the caller to have produced it.
    pub(crate) fn from_key<E>(primary_key: Cow<'_, [u8]>) -> Self
    where
        E: Entity,
    {
        Self {
            id: primary_key.into_owned(),
            table_name: E::TABLE_NAME,
        }
    }

    /// Build the id of an entity instance.
    ///
    /// Note that this asks the entity for its primary key, which for some entities means hashing
    /// their contents. Where the id is already available — as a cache key, say — reuse it rather than
    /// deriving it again.
    pub(crate) fn from_entity<E>(entity: &E) -> Self
    where
        E: Entity,
    {
        Self::from_key::<E>(entity.primary_key().bytes())
    }

    /// Build the id of the record of type `E` with this primary key.
    pub(crate) fn from_primary_key<E>(primary_key: &E::PrimaryKey) -> Self
    where
        E: Entity,
    {
        Self::from_key::<E>(primary_key.bytes())
    }

    /// Build the id of the record of type `E` with this primary key, in its borrowed form.
    ///
    /// Equal to what [`Self::from_primary_key`] produces for the owned form of the same key, so the
    /// two are interchangeable for lookups.
    pub(crate) fn from_borrowed_primary_key<E>(primary_key: &E::BorrowedPrimaryKey) -> Self
    where
        E: Entity + BorrowPrimaryKey,
    {
        Self::from_key::<E>(primary_key.to_owned().bytes())
    }
}
