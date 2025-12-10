use idb::builder::DatabaseBuilder;

use crate::{
    CryptoKeystoreError, CryptoKeystoreResult, Database, DatabaseKey,
    connection::{
        KeystoreDatabaseConnection, TransactionWrapper, platform::wasm::WasmStorageWrapper,
        storage::WasmEncryptedStorage,
    },
};

impl Database {
    /// Make sure you haven't got another open connection before calling this.
    pub(crate) async fn migration_connection(
        previous_builder: DatabaseBuilder,
        key: &DatabaseKey,
    ) -> CryptoKeystoreResult<KeystoreDatabaseConnection> {
        let idb_during_migration = previous_builder.build().await?;
        let wrapper_during_migration = WasmStorageWrapper::Persistent(idb_during_migration);
        let storage_during_migration = WasmEncryptedStorage::new(key, wrapper_during_migration);
        Ok(KeystoreDatabaseConnection::from_inner(storage_during_migration))
    }

    /// Open a transaction on the provided connection, do some generic work on the transaction, commit the
    /// transaction and close the connection.
    pub(crate) async fn migration_transaction<F>(
        db_during_migration: KeystoreDatabaseConnection,
        migration_work: F,
    ) -> CryptoKeystoreResult<()>
    where
        F: AsyncFnOnce(&mut TransactionWrapper) -> CryptoKeystoreResult<()>,
    {
        let idb = match db_during_migration.storage().storage {
            WasmStorageWrapper::Persistent(ref database) => database,
            WasmStorageWrapper::InMemory(_) => {
                return Err(CryptoKeystoreError::MigrationFailed(
                    "In-memory keystore doesn't support migrations".into(),
                ));
            }
        };
        let stores = idb.store_names();
        let mut conn = db_during_migration.conn().await;
        let mut transaction = conn.new_transaction(&stores).await?;

        migration_work(&mut transaction).await?;

        let result = transaction.commit_tx().await;
        db_during_migration.close().await?;
        if result.is_err() {
            return Err(CryptoKeystoreError::MigrationFailed(
                "Migration transaction hasn't been cmmitted".into(),
            ));
        }
        Ok(())
    }
}
