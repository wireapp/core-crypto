use core::fmt;
use std::borrow::Cow;

use crate::{
    CryptoKeystoreError, CryptoKeystoreResult,
    traits::{BorrowPrimaryKey, Entity, KeyType, OwnedKeyType as _},
};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct EntityId {
    table_name: &'static str,
    id: Vec<u8>,
}

impl fmt::Display for EntityId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Self { table_name, id } = self;
        write!(f, "{table_name:?}: {}", hex::encode(id))
    }
}

impl EntityId {
    pub(crate) fn matches_type<E>(&self) -> bool
    where
        E: Entity,
    {
        self.table_name == E::TABLE_NAME
    }

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

    pub(crate) fn from_key<E>(primary_key: Cow<'_, [u8]>) -> Self
    where
        E: Entity,
    {
        Self {
            id: primary_key.into_owned(),
            table_name: E::TABLE_NAME,
        }
    }

    pub(crate) fn from_entity<E>(entity: &E) -> Self
    where
        E: Entity,
    {
        Self::from_key::<E>(entity.primary_key().bytes())
    }

    pub(crate) fn from_primary_key<E>(primary_key: &E::PrimaryKey) -> Self
    where
        E: Entity,
    {
        Self::from_key::<E>(primary_key.bytes())
    }

    pub(crate) fn from_borrowed_primary_key<E>(primary_key: &E::BorrowedPrimaryKey) -> Self
    where
        E: Entity + BorrowPrimaryKey,
    {
        Self::from_key::<E>(primary_key.to_owned().bytes())
    }
}
