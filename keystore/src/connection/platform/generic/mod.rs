use std::ops::Deref;
use std::path::Path;

use zeroize::Zeroize as _;

use crate::{CryptoKeystoreError, CryptoKeystoreResult};
use crate::connection::{DatabaseConnection, DatabaseConnectionRequirements, DatabaseKey};
use async_lock::{Mutex, MutexGuard};
use blocking::unblock;
use rusqlite::{Transaction, functions::FunctionFlags};

#[cfg(feature = "log-queries")]
use rusqlite::trace::{TraceEvent, TraceEventCodes};

#[cfg(target_os = "ios")]
mod ios_wal_compat;

refinery::embed_migrations!("src/connection/platform/generic/migrations");

pub struct TransactionWrapper<'conn> {
    transaction: Transaction<'conn>,
}

impl TransactionWrapper<'_> {
    // this is async just to conform with the wasm impl
    pub(crate) async fn commit_tx(self) -> CryptoKeystoreResult<()> {
        // It's really not ideal to do potentially-heavy IO such as committing a transaction
        // within the async context, because Rust async depends on inserting cooperative yields
        // in appropriate places, and blocking functions simply do not have those. This is going
        // to bind up the whole async executor every time we try to commit the transaction, for
        // the entire duration of the execution of the transaction.
        //
        // We can't even do `unblock(|| transaction.commit())` here becase `Transaction: !Send`.
        //
        // Hopefully either WPB-14326, WPB-14327, or WPB-15766 will open a path to a unified
        // async database which can give us better performance characteristics than this.
        self.transaction.commit().map_err(Into::into)
    }
}

impl<'conn> From<Transaction<'conn>> for TransactionWrapper<'conn> {
    fn from(transaction: Transaction<'conn>) -> Self {
        TransactionWrapper { transaction }
    }
}

impl<'conn> Deref for TransactionWrapper<'conn> {
    type Target = Transaction<'conn>;

    fn deref(&self) -> &Self::Target {
        &self.transaction
    }
}

// SAFETY: This is **UNSAFE**. Transactions are intentionally `!Send`,
// and we do nothing to provide guarantees which would make them safe to share between threads.
// See https://github.com/rusqlite/rusqlite/issues/697 for discussion on this.
//
// Unfortunately, everything breaks for now if we simply remove this. This is going to take
// non-trivial work to fix. See https://wearezeta.atlassian.net/browse/WPB-15767.
unsafe impl Send for TransactionWrapper<'_> {}
// SAFETY: This is **UNSAFE**. See above.
unsafe impl Sync for TransactionWrapper<'_> {}

#[derive(Debug)]
pub struct SqlCipherConnection {
    conn: Mutex<rusqlite::Connection>,
    path: String,
}

// SAFETY: An `Arc` is unnecessary as `SqlCipherConnection: !Clone`, and there is a `Mutex`
// internally which ensures unique access.
unsafe impl Send for SqlCipherConnection {}
// SAFETY: An `Arc` is unnecessary as `SqlCipherConnection: !Clone`, and there is a `Mutex`
// internally which ensures unique access.
unsafe impl Sync for SqlCipherConnection {}

impl SqlCipherConnection {
    fn init_with_key(path: &str, key: &DatabaseKey) -> CryptoKeystoreResult<Self> {
        let mut conn = rusqlite::Connection::open(path)?;

        #[cfg(feature = "log-queries")]
        conn.trace_v2(TraceEventCodes::SQLITE_TRACE_STMT, Some(Self::log_query));

        Self::set_key(&mut conn, key)?;

        // ? iOS WAL journaling fix; see details here: https://github.com/sqlcipher/sqlcipher/issues/255
        #[cfg(target_os = "ios")]
        ios_wal_compat::handle_ios_wal_compat(&conn, path)?;

        // Enable WAL journaling mode
        conn.pragma_update(None, "journal_mode", "wal")?;

        // Disable FOREIGN KEYs - The 2 step blob writing process invalidates foreign key checks unfortunately
        conn.pragma_update(None, "foreign_keys", "OFF")?;

        Self::run_migrations(&mut conn)?;

        let conn = Self {
            path: path.into(),
            conn: Mutex::new(conn),
        };

        Ok(conn)
    }

    #[cfg(feature = "log-queries")]
    fn log_query(event: TraceEvent) {
        if let TraceEvent::Stmt(_, sql) = event {
            log::info!("{sql}")
        }
    }

    fn set_key(conn: &mut rusqlite::Connection, key: &DatabaseKey) -> CryptoKeystoreResult<()> {
        // Make sqlite use raw key data, without key derivation. Also make sure to zeroize
        // the string containing the key after the call.
        let mut key = format!("x'{}'", hex::encode(key));
        let result = conn.pragma_update(None, "key", &key);
        key.zeroize();
        result.map_err(Into::into)
    }

    fn init_with_key_in_memory(key: &DatabaseKey) -> CryptoKeystoreResult<Self> {
        let mut conn = rusqlite::Connection::open("")?;

        #[cfg(feature = "log-queries")]
        conn.trace_v2(TraceEventCodes::SQLITE_TRACE_STMT, Some(Self::log_query));

        Self::set_key(&mut conn, key)?;

        // Disable FOREIGN KEYs - The 2 step blob writing process invalidates foreign key checks unfortunately
        conn.pragma_update(None, "foreign_keys", "OFF")?;

        // Need to run migrations also in memory to make sure expected tables exist.
        Self::run_migrations(&mut conn)?;

        let conn = Self {
            path: "".into(),
            conn: Mutex::new(conn),
        };

        Ok(conn)
    }

    pub async fn migrate_db_key_type_to_bytes(
        path: &str,
        old_key: &str,
        new_key: &DatabaseKey,
    ) -> CryptoKeystoreResult<()> {
        let mut conn = rusqlite::Connection::open(Path::new(path))?;

        conn.pragma_update(None, "key", old_key)?;

        // ? iOS WAL journaling fix; see details here: https://github.com/sqlcipher/sqlcipher/issues/255
        #[cfg(target_os = "ios")]
        ios_wal_compat::handle_ios_wal_compat(&conn, path)?;

        // Enable WAL journaling mode
        conn.pragma_update(None, "journal_mode", "wal")?;

        // Disable FOREIGN KEYs - The 2 step blob writing process invalidates foreign key checks unfortunately
        conn.pragma_update(None, "foreign_keys", "OFF")?;

        Self::run_migrations(&mut conn)?;

        // Rekey the database.
        Self::rekey(&mut conn, new_key)
    }

    fn rekey(conn: &mut rusqlite::Connection, new_key: &DatabaseKey) -> CryptoKeystoreResult<()> {
        let mut key = format!("x'{}'", hex::encode(new_key));
        let result = conn.pragma_update(None, "rekey", &key);
        key.zeroize();
        Ok(result?)
    }

    pub async fn conn(&self) -> MutexGuard<'_, rusqlite::Connection> {
        self.conn.lock().await
    }

    pub async fn wipe(self) -> CryptoKeystoreResult<()> {
        if self.path.is_empty() {
            return Ok(());
        }

        let path = self.path.clone();

        unblock(|| self.close()).await?;
        async_fs::remove_file(&path).await?;
        Ok(())
    }

    fn close(self) -> CryptoKeystoreResult<()> {
        let conn = self.conn.into_inner();
        conn.close().map_err(|(_, e)| e.into())
    }

    /// Export a copy of the database to the specified path using VACUUM INTO.
    /// This creates a fully vacuumed and optimized copy of the database.
    /// The copy will be encrypted with the same key as the source database.
    ///
    /// # Arguments
    /// * `destination_path` - The file path where the database copy should be created
    ///
    /// # Errors
    /// Returns an error if:
    /// - The database is in-memory (cannot export in-memory databases)
    /// - The destination path is invalid
    /// - The VACUUM INTO operation fails
    pub async fn export_copy(&self, destination_path: &str) -> CryptoKeystoreResult<()> {
        if self.path.is_empty() {
            return Err(CryptoKeystoreError::NotSupported(
                "Cannot export in-memory database".to_string(),
            ));
        }

        let conn = self.conn().await;
        conn.execute("VACUUM INTO ?1", [destination_path])?;

        Ok(())
    }

    fn run_migrations(conn: &mut rusqlite::Connection) -> CryptoKeystoreResult<()> {
        conn.create_scalar_function("sha256_blob", 1, FunctionFlags::SQLITE_DETERMINISTIC, |ctx| {
            let input_blob = ctx.get::<Vec<u8>>(0)?;
            Ok(crate::sha256(&input_blob))
        })?;
        let report = migrations::runner().run(&mut *conn).map_err(Box::new)?;
        if let Some(version) = report.applied_migrations().iter().map(|m| m.version()).max() {
            conn.pragma_update(None, "schema_version", version)?;
        }

        Ok(())
    }
}

impl DatabaseConnectionRequirements for SqlCipherConnection {}

#[cfg_attr(target_family = "wasm", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_family = "wasm"), async_trait::async_trait)]
impl<'a> DatabaseConnection<'a> for SqlCipherConnection {
    type Connection = MutexGuard<'a, rusqlite::Connection>;

    async fn open(name: &str, key: &DatabaseKey) -> CryptoKeystoreResult<Self> {
        let name = name.to_string();
        let key = key.clone();
        Ok(unblock(move || Self::init_with_key(&name, &key)).await?)
    }

    async fn open_in_memory(key: &DatabaseKey) -> CryptoKeystoreResult<Self> {
        let key = key.clone();
        Ok(unblock(move || Self::init_with_key_in_memory(&key)).await?)
    }

    async fn update_key(&mut self, new_key: &DatabaseKey) -> CryptoKeystoreResult<()> {
        let mut conn = self.conn().await;
        Self::rekey(&mut conn, new_key)
    }

    async fn close(self) -> CryptoKeystoreResult<()> {
        unblock(|| self.close()).await
    }

    async fn wipe(self) -> CryptoKeystoreResult<()> {
        self.wipe().await?;
        Ok(())
    }
}

#[cfg(test)]
mod export_test {
    use futures_lite::future;

    use crate::{
        ConnectionType, Database, DatabaseKey,
    };

    const DB: &[u8] = include_bytes!("../../../../../crypto-ffi/bindings/jvm/src/test/resources/db-v10002003.sqlite");
    const OLD_KEY: &str = "secret";

    #[test]
    fn can_export_database_copy() {
        future::block_on(async {
            // Create temporary files for source and destination
            let source_path = format!("./test_export_source_{}.db", rand::random::<u32>());
            let dest_path = format!("./test_export_dest_{}.db", rand::random::<u32>());

            // Write test database
            std::fs::write(&source_path, DB).unwrap();

            // Migrate the database to use the new key format
            let key = DatabaseKey::generate();
            Database::migrate_db_key_type_to_bytes(&source_path, OLD_KEY, &key).await.unwrap();

            // Open the database and export it
            let db = Database::open(ConnectionType::Persistent(&source_path), &key)
                .await
                .unwrap();

            // Export the database
            db.export_copy(&dest_path).await.unwrap();

            // Verify the exported database can be opened with the same key
            let exported_db = Database::open(ConnectionType::Persistent(&dest_path), &key)
                .await
                .unwrap();

            // Close databases before cleanup
            drop(db);
            drop(exported_db);

            // Cleanup
            let _ = std::fs::remove_file(&source_path);
            let _ = std::fs::remove_file(&dest_path);
            let _ = std::fs::remove_file(format!("{}-wal", source_path));
            let _ = std::fs::remove_file(format!("{}-shm", source_path));
            let _ = std::fs::remove_file(format!("{}-wal", dest_path));
            let _ = std::fs::remove_file(format!("{}-shm", dest_path));
        });
    }

    #[test]
    fn cannot_export_in_memory_database() {
        future::block_on(async {
            let key = DatabaseKey::generate();
            let db = Database::open(ConnectionType::InMemory, &key).await.unwrap();

            let result = db.export_copy("/tmp/should_fail.db").await;

            assert!(result.is_err(), "Exporting in-memory database should fail");
            assert!(
                result.unwrap_err().to_string().contains("in-memory"),
                "Error should mention in-memory database"
            );
        });
    }
}
