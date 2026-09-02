use openmls_traits::key_store::MlsEntity;

use crate::{CryptoKeystoreError, CryptoKeystoreResult, Database, Transaction, transaction::read_mls_entity};

/// convenience methods to modify the in-flight transaction
impl Database {
    /// Do an operation on an existing keystore transaction.
    ///
    /// This does not create, commit, or abort an existing transaction; it just provides a standardized
    /// helper to acquire it while creating appropriate errors.
    async fn with_transaction<R>(&self, operation: impl AsyncFnOnce(&Transaction) -> R) -> CryptoKeystoreResult<R> {
        let guard = self.transaction.lock().await;
        let transaction = guard
            .as_ref()
            .ok_or(CryptoKeystoreError::MutatingOperationWithoutTransaction)?
            .upgrade()
            .await
            .ok_or(CryptoKeystoreError::MutatingOperationWithoutTransaction)?;

        Ok(operation(&transaction).await)
    }
}

#[inline(always)]
pub fn deser<T: MlsEntity>(bytes: &[u8]) -> Result<T, CryptoKeystoreError> {
    Ok(postcard::from_bytes(bytes)?)
}

#[inline(always)]
pub fn ser<T: MlsEntity>(value: &T) -> Result<Vec<u8>, CryptoKeystoreError> {
    Ok(postcard::to_stdvec(value)?)
}

#[cfg_attr(target_os = "unknown", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_os = "unknown"), async_trait::async_trait)]
impl openmls_traits::key_store::OpenMlsKeyStore for Database {
    type Error = CryptoKeystoreError;

    async fn store<V: MlsEntity + Sync>(&self, id: &[u8], value: &V) -> Result<(), Self::Error>
    where
        Self: Sized,
    {
        self.with_transaction(async |tx| tx.store(id, value).await)
            .await
            .flatten()
    }

    async fn read<V: MlsEntity>(&self, id: &[u8]) -> Option<V>
    where
        Self: Sized,
    {
        let conn = self.conn().await;
        read_mls_entity(&conn, id)
    }

    async fn delete<V: MlsEntity>(&self, id: &[u8]) -> Result<(), Self::Error> {
        self.with_transaction(async |tx| tx.delete::<V>(id).await)
            .await
            .flatten()
    }
}
