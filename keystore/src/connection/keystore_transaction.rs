//! The methods in this module handle keystore transactions.
//!
//! Keystore transactions are "fake", in-memory persistence of database operations over time.
//! They're required because actual [`rusqlite::Transaction`] is `!Send + !Sync`, and we need
//! `Send` at a minimum in order to keep the transaction around and manipulate it concurrently
//! from various tasks.

use crate::{
    CryptoKeystoreError, CryptoKeystoreResult, Database,
    traits::{BorrowPrimaryKey, Entity, EntityDatabaseMutation, EntityDeleteBorrowed},
    transaction::KeystoreTransaction,
};

/// These impls control the keystore transaction lifecycle.
impl Database {
    /// Waits for the current transaction to be committed or rolled back, then starts a new one.
    pub async fn new_transaction(&self) -> CryptoKeystoreResult<()> {
        let semaphore = self.transaction_semaphore.acquire_arc().await;
        let mut transaction_guard = self.transaction.lock().await;
        debug_assert!(
            transaction_guard.is_none(),
            "transaction already existed despite acquiring semaphore"
        );

        // we'll need to adjust the `KeystoreTransaction` constructor not to require an Arc version of the semaphore
        // guard
        let transaction = KeystoreTransaction::new(semaphore).await?;
        *transaction_guard = Some(transaction);
        Ok(())
    }

    /// Start a new transaction if no other transaction is currently in progress.
    ///
    /// If a transaction is currently in progress, this will produce a `TransactionInProgress` error.
    pub async fn try_new_immediate_transaction(&self) -> CryptoKeystoreResult<()> {
        let semaphore = self
            .transaction_semaphore
            .try_acquire_arc()
            .ok_or(CryptoKeystoreError::TransactionInProgress)?;
        let mut transaction_guard = self.transaction.lock().await;
        debug_assert!(
            transaction_guard.is_none(),
            "transaction already existed despite acquiring semaphore"
        );

        // we'll need to adjust the `KeystoreTransaction` constructor not to require an Arc version of the semaphore
        // guard
        let transaction = KeystoreTransaction::new(semaphore).await?;
        *transaction_guard = Some(transaction);
        Ok(())
    }

    pub async fn commit_transaction(&self) -> CryptoKeystoreResult<()> {
        let mut transaction_guard = self.transaction.lock().await;
        let Some(transaction) = transaction_guard.take() else {
            return Err(CryptoKeystoreError::MutatingOperationWithoutTransaction);
        };
        debug_assert!(
            transaction_guard.is_none(),
            "taking the transaction leaves `None` behind"
        );

        transaction.commit(self).await?;
        Ok(())
    }

    pub async fn rollback_transaction(&self) -> CryptoKeystoreResult<()> {
        let mut transaction_guard = self.transaction.lock().await;
        if transaction_guard.is_none() {
            return Err(CryptoKeystoreError::MutatingOperationWithoutTransaction);
        };
        *transaction_guard = None;
        Ok(())
    }

    /// Do an operation on a keystore transaction on this database.
    ///
    /// This is a convenience method abstracting over [`Self::new_transaction`],
    /// [`Self::commit_transaction`], and [`Self::rollback_transaction`].
    ///
    /// If the operation succeeds, the transaction is committed.
    /// Otherwise, it is rolled back.
    pub async fn transactionally<R>(
        &self,
        operation: impl AsyncFnOnce(&KeystoreTransaction) -> CryptoKeystoreResult<R>,
    ) -> CryptoKeystoreResult<R> {
        // we don't actually delegate to the internal lifecycle constructs because
        // they include mutations and checks we don't need, given that we
        // know that this function's lifetime exceeds that of the internal transaction.
        let semaphore = self.transaction_semaphore.acquire_arc().await;
        let transaction = KeystoreTransaction::new(semaphore).await?;

        let result = operation(&transaction).await;
        if result.is_ok() {
            transaction.commit(self).await?;
        }
        // otherwise implicit abort on tx drop

        result
    }

    /// Do an operation on an existing keystore transaction.
    ///
    /// This does not create, commit, or abort an existing transaction; it just provides a standardized
    /// helper to acquire it while creating appropriate errors.
    pub(crate) async fn with_transaction<R>(
        &self,
        operation: impl AsyncFnOnce(&KeystoreTransaction) -> CryptoKeystoreResult<R>,
    ) -> CryptoKeystoreResult<R> {
        let guard = self.transaction.lock().await;
        let Some(transaction) = guard.as_ref() else {
            return Err(CryptoKeystoreError::MutatingOperationWithoutTransaction);
        };
        operation(transaction).await
    }
}

/// These impls are convenience methods to modify the keystore transaction.
///
/// Be aware that we are likely to remove these in the future: WPB-23951
impl Database {
    pub async fn save<E>(&self, entity: E) -> CryptoKeystoreResult<E::AutoGeneratedFields>
    where
        E: Entity + EntityDatabaseMutation + Send + Sync,
    {
        self.with_transaction(async |transaction| transaction.save(entity).await)
            .await
    }

    pub async fn remove<E>(&self, id: &E::PrimaryKey) -> CryptoKeystoreResult<()>
    where
        E: Entity + EntityDatabaseMutation,
    {
        self.with_transaction(async |transaction| transaction.remove::<E>(id).await)
            .await
    }

    pub async fn remove_borrowed<E>(&self, id: &E::BorrowedPrimaryKey) -> CryptoKeystoreResult<()>
    where
        E: Entity + EntityDatabaseMutation + BorrowPrimaryKey + EntityDeleteBorrowed,
    {
        self.with_transaction(async |transaction| transaction.remove_borrowed::<E>(id).await)
            .await
    }
}
