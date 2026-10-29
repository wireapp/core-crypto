use core_crypto_keystore::CryptoKeystoreError;

use super::TransactionContextInner;

impl TransactionContextInner {
    /// Run `operation` inside a savepoint of this transaction.
    ///
    /// If `operation` fails, its database writes are rolled back.
    pub(crate) async fn with_savepoint<T, E>(
        &self,
        savepoint_name: &str,
        operation: impl AsyncFnOnce() -> Result<T, E>,
        map_err: impl Fn(&'static str) -> Box<dyn FnOnce(CryptoKeystoreError) -> E>,
    ) -> Result<T, E> {
        self.transaction
            .with_savepoint(savepoint_name, operation, map_err)
            .await
    }
}
