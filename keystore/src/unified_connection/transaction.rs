// For now we suppress all unused warnings because those are spurious, the result of TODO impls.
#![expect(unused)]
use crate::{CryptoKeystoreError, CryptoKeystoreResult, transaction::KeystoreTransaction};

impl super::Database {
    /// Waits for the current transaction to be committed or rolled back, then starts a new one.
    pub async fn new_transaction(&self) -> CryptoKeystoreResult<()> {
        let semaphore = self.transaction_semaphore.acquire().await;
        let mut transaction_guard = self.transaction.lock().await;
        // we'll need to adjust the `KeystoreTransaction` constructor not to require an Arc version of the semaphore guard
        let transaction = todo!(); // KeystoreTransaction::new(semaphore).await?
        *transaction_guard = Some(transaction);
        Ok(())
    }

    pub async fn commit_transaction(&self) -> CryptoKeystoreResult<()> {
        let mut transaction_guard = self.transaction.lock().await;
        let Some(transaction) = transaction_guard.as_ref() else {
            return Err(CryptoKeystoreError::MutatingOperationWithoutTransaction);
        };
        // we'll need to adjust the `KeystoreTransaction::commit` interface to accept this kind of database
        todo!("transaction.commit(self).await?");
        *transaction_guard = None;
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
}
