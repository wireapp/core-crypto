use async_trait::async_trait;

use crate::traits::OwnedKeyType;

/// Something which has a distinct primary key which can uniquely identify it.
pub trait PrimaryKey {
    /// Each distinct `PrimaryKey` uniquely identifies either 0 or 1 instance.
    ///
    /// This constraint should be enforced at the DB level.
    type PrimaryKey: OwnedKeyType;

    /// Get this entity's primary key.
    ///
    /// This must return an owned type, because there are some entities for which only owned primary keys are possible.
    /// However, entities which have primary keys owned within the entity itself should consider also implementing
    /// [`BorrowPrimaryKey`] for greater efficiency.
    fn primary_key(&self) -> Self::PrimaryKey;
}

/// Something whose primary key can be borrowed as a distinct type.
///
/// i.e. `String`, `Vec<u8>`, etc.
pub trait BorrowPrimaryKey: PrimaryKey {
    type BorrowedPrimaryKey: ?Sized + ToOwned<Owned = Self::PrimaryKey>;

    /// Borrow this entity's primary key without copying any data.
    ///
    /// This borrowed key has a lifetime tied to that of this entity.
    fn borrow_primary_key(&self) -> &Self::BorrowedPrimaryKey;
}
