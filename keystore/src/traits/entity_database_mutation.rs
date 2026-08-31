use crate::{
    CryptoKeystoreResult, Transactionlike,
    traits::{BorrowPrimaryKey, Entity},
};

/// Extend an [`Entity`] with db-mutating operations which can be performed when provided with a transaction.
pub trait EntityDatabaseMutation: Entity {
    /// Save this entity to the database in the context of this transaction.
    ///
    /// The transaction is required instead of a simple connection to give us type-level assurances
    /// that we only mutate the database within the context of a transaction; every mutation can
    /// be rolled back if necessary.
    ///
    /// Unlike in earlier iterations of this trait, saving makes no automatic adjustment to the
    /// entity being saved. Entities requiring a `pre_save` method must implement this manually.
    fn save<'a, Tx>(&self, tx: &'a Tx) -> CryptoKeystoreResult<()>
    where
        &'a Tx: Into<Transactionlike<'a>>;

    /// Use the transaction's inteface to delete this entity from the database.
    ///
    /// Returns `true` if at least one entity was deleted, or `false` if the id was not found in the database.
    ///
    /// For entites whose primary key has a distinct borrowed type, it is best to implement this as a direct
    /// passthrough:
    ///
    /// ```rust,ignore
    /// fn delete<'a, Tx>(tx: &'a Tx, id: &Self::PrimaryKey) -> CryptoKeystoreResult<bool>
    /// where
    ///     &'a Tx: Into<Transactionlike<'a>>,
    /// {
    ///     <Self as EntityDeleteBorrowed>::delete_borrowed(tx, id)
    /// }
    /// ```
    fn delete<'a, Tx>(tx: &'a Tx, id: &Self::PrimaryKey) -> CryptoKeystoreResult<bool>
    where
        Transactionlike<'a>: From<&'a Tx>;
}

/// Extend an [`Entity`] with db-mutating operations which can be performed when provided with a transaction.
pub trait EntityDeleteBorrowed: EntityDatabaseMutation + BorrowPrimaryKey {
    /// Delete an entity by a borrowed form of its primary key.
    fn delete_borrowed<'a, Tx>(tx: &'a Tx, id: Self::BorrowedPrimaryKey<'_>) -> CryptoKeystoreResult<bool>
    where
        &'a Tx: Into<Transactionlike<'a>>;
}
