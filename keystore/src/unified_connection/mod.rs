mod encryption;
mod entity_extension_methods;
mod fetch_from_database;
mod filesystem;
#[cfg(target_os = "unknown")]
mod idb_migration;
#[cfg(target_os = "ios")]
mod ios_wal_compat;
mod keystore_transaction;
mod migrations;
#[cfg(target_os = "unknown")]
mod os_unknown;

use std::sync::Arc;

use async_lock::{Mutex, MutexGuard, Semaphore};
use rusqlite::Connection;
#[cfg(feature = "log-queries")]
use rusqlite::trace::{TraceEvent, TraceEventCodes};

pub(crate) use self::filesystem::Filesystem;
#[cfg(target_os = "unknown")]
pub use self::idb_migration::{delete_legacy_idb, legacy_idb_exists};
pub use self::migrations::migrate_db_key_type_to_bytes;
use crate::{
    CryptoKeystoreResult, DatabaseKey, transaction::KeystoreTransaction,
    unified_connection::migrations::MigrationTarget,
};

#[cfg(feature = "log-queries")]
fn log_query(event: TraceEvent) {
    if let TraceEvent::Stmt(_, sql) = event {
        log::info!("{sql}")
    }
}

// Intentionally not `Clone`; outer users should wrap this entire thing in an `Arc` (or `Arc<Mutex<Option<Self>>>`
// etc) as required for their desired semantics.
#[derive(Debug)]
pub struct Database {
    // internal connection; mutexed in order to ensure unique access
    // and provide `Sync`
    conn: Mutex<Connection>,
    // handler with which to delete the database;
    // mutexed to provide `Sync`
    pub(crate) filesystem: Mutex<Box<dyn Filesystem>>,
    pub(crate) transaction: Mutex<Option<KeystoreTransaction>>,
    // we need this `Arc` so we can create an owned guard, so that
    // `self.transaction` doesn't need a self-referential lifetime.
    transaction_semaphore: Arc<Semaphore>,
}

impl Database {
    /// Open an encrypted `Database` at the provided location.
    ///
    /// This function is the internal implementation for [`Self::open`]; that method should be generally preferred.
    async fn open_internal(
        path: &str,
        database_key: &DatabaseKey,
    ) -> CryptoKeystoreResult<(Connection, Box<dyn Filesystem>)> {
        #[cfg(target_os = "unknown")]
        let (conn, filesystem) = { os_unknown::open(path, database_key).await? };

        #[cfg(not(target_os = "unknown"))]
        let (conn, filesystem) = {
            let exists = std::fs::exists(path)?;
            let mut conn = Connection::open(path)?;
            if exists {
                encryption::decrypt(&mut conn, database_key)?;
            } else {
                encryption::key(&mut conn, database_key)?;
            }
            (conn, filesystem::NativeFs)
        };

        let filesystem = Box::new(filesystem);
        Ok((conn, filesystem))
    }

    /// Set up the database from a connection
    ///
    /// The connection must already be configured for encryption if appropriate.
    ///
    /// Sets appropriate pragmas and performs migrations and general initialization work.
    fn init(
        mut conn: Connection,
        filesystem: Box<dyn Filesystem>,
        migration_target: MigrationTarget,
    ) -> CryptoKeystoreResult<Self> {
        const ALLOWED_CONCURRENT_TRANSACTIONS_COUNT: usize = 1;

        #[cfg(feature = "log-queries")]
        conn.trace_v2(TraceEventCodes::SQLITE_TRACE_STMT, Some(log_query));

        // path is an empty string for in-memory databases
        if let Some(path) = conn.path()
            && !path.is_empty()
        {
            // ? iOS WAL journaling fix; see details here: https://github.com/sqlcipher/sqlcipher/issues/255
            #[cfg(target_os = "ios")]
            ios_wal_compat::handle_ios_wal_compat(&conn, path)?;

            // Enable WAL journaling mode when not in memory
            conn.pragma_update(None, "journal_mode", "wal")?;
        }

        migrations::run_migrations(&mut conn, migration_target)?;
        let conn = conn.into();

        Ok(Self {
            conn,
            filesystem: filesystem.into(),
            transaction: Default::default(),
            transaction_semaphore: Arc::new(Semaphore::new(ALLOWED_CONCURRENT_TRANSACTIONS_COUNT)),
        })
    }

    /// Open an encrypted `Database` at the provided location.
    ///
    /// When compiled with `target_os = "unknown"`, this opens a database encrypted via
    /// sqlite3-multiple-ciphers using its default encryption mechanism, stored in IndexedDB
    /// via the `relaxed-idb` shim.
    ///
    /// When compiled normally, this opens a database encrypted via sqlcipher at a path in the
    /// local filesystem.
    pub async fn open(path: &str, database_key: &DatabaseKey) -> CryptoKeystoreResult<Arc<Self>> {
        let (conn, filesystem) = Self::open_internal(path, database_key).await?;
        Self::init(conn, filesystem, MigrationTarget::Latest).map(Into::into)
    }

    /// Open an in-memory `Database`.
    ///
    /// In-memory databases are never encrypted.
    pub fn open_in_memory() -> CryptoKeystoreResult<Arc<Self>> {
        let connection = Connection::open_in_memory()?;
        Self::init(connection, Box::new(filesystem::Nop), MigrationTarget::Latest).map(Into::into)
    }

    /// Open an encrypted `Database` at the provided location.
    ///
    /// Acts as `open`, but only migrates to the specified schema version.
    ///
    /// Note: this is known to work because `Self::open_internal` will only ever perform
    /// a partial migration when `target_os = "unknown"`, where this function is not defined.
    /// Use caution when adjusting the cfg flags here!
    #[cfg(all(test, not(target_os = "unknown")))]
    pub(crate) async fn open_at_schema_version(
        path: &str,
        database_key: &DatabaseKey,
        migration_target: MigrationTarget,
    ) -> CryptoKeystoreResult<Self> {
        let (conn, filesystem) = Self::open_internal(path, database_key).await?;
        Self::init(conn, filesystem, migration_target)
    }

    /// Change the encryption key for this database.
    pub async fn update_key(&self, new_key: &DatabaseKey) -> CryptoKeystoreResult<()> {
        let mut guard = self.conn.lock().await;
        encryption::rekey(&mut guard, new_key)
    }

    /// Wait for any running transaction to finish, then take the connection out of this database,
    /// preventing this from being used again.
    async fn take(self) -> CryptoKeystoreResult<(Connection, Box<dyn Filesystem>)> {
        let _semaphore = self.transaction_semaphore.acquire().await;
        Ok((self.conn.into_inner(), self.filesystem.into_inner()))
    }

    // Close this database connection
    pub async fn close(self) -> CryptoKeystoreResult<()> {
        let (conn, _fs) = self.take().await?;
        conn.close().map_err(|(_conn, err)| err)?;
        Ok(())
    }

    /// Close and remove this database.
    ///
    /// This deletes the database, including its encryption key.
    /// Future opens will always succeed with any arbitrary encryption key; they will
    /// simply open an empty database.
    pub async fn wipe(self) -> CryptoKeystoreResult<()> {
        let (conn, fs) = self.take().await?;
        conn.execute_batch(
            "
            PRAGMA writable_schema = 1;
            DELETE FROM sqlite_master WHERE type IN ('table', 'index', 'trigger');
            PRAGMA writable_schema = 0;
            VACUUM;
        ",
        )?;
        let location = conn.path().map(ToOwned::to_owned);
        conn.close().map_err(|(_conn, err)| err)?;
        if let Some(path) = location {
            // not in-memory
            fs.delete(&path).await?;
        }
        Ok(())
    }

    /// Get a reference to this database's connection.
    pub(crate) async fn conn(&self) -> MutexGuard<'_, Connection> {
        self.conn.lock().await
    }

    /// Get the location of the database.
    ///
    /// Returns None if the database is in-memory.
    pub async fn location(&self) -> Option<String> {
        self.conn()
            .await
            .path()
            .filter(|s| !s.is_empty())
            .map(ToString::to_string)
    }

    /// Export a copy of the database to the specified path using VACUUM INTO.
    ///
    /// This creates a fully vacuumed and optimized copy of the database.
    /// The copy will be encrypted with the same key as the source database.
    ///
    /// # Arguments
    /// * `destination_path` - The file path where the database copy should be created
    #[cfg(not(target_os = "unknown"))]
    pub async fn export_copy(&self, destination_path: &str) -> CryptoKeystoreResult<()> {
        self.conn().await.execute("VACUUM INTO ?1", [destination_path])?;
        Ok(())
    }
}

#[cfg(all(test, not(target_os = "unknown")))]
mod export_test {
    use futures_lite::future;

    use crate::unified_connection::{Database, DatabaseKey};

    #[test]
    fn can_export_database_copy() {
        future::block_on(async {
            // Create temporary directory
            let temp_dir = tempfile::tempdir().unwrap();
            let source_path = temp_dir.path().join("test_export_source.db");
            let dest_path = temp_dir.path().join("test_export_dest.db");

            // Write test database
            std::fs::write(&source_path, super::migrations::test::DB).unwrap();

            // Migrate the database to use the new key format
            let key = DatabaseKey::generate();
            super::migrations::migrate_db_key_type_to_bytes(
                source_path.to_str().unwrap(),
                super::migrations::test::OLD_KEY,
                &key,
            )
            .await
            .unwrap();

            // Open the database
            let db = Database::open(source_path.to_str().unwrap(), &key).await.unwrap();

            // Insert test data into a test table
            let test_data = b"test data for export verification";
            let test_id = 12345;
            {
                // Create a test table
                db.conn()
                    .await
                    .execute(
                        "CREATE TABLE IF NOT EXISTS test_export_data (id INTEGER PRIMARY KEY, data BLOB)",
                        [],
                    )
                    .unwrap();

                // Insert test data
                db.conn()
                    .await
                    .execute(
                        "INSERT INTO test_export_data (id, data) VALUES (?1, ?2)",
                        [&test_id as &dyn rusqlite::ToSql, &test_data.as_slice()],
                    )
                    .unwrap();
            }

            // Export the database
            db.export_copy(dest_path.to_str().unwrap()).await.unwrap();

            // Verify the exported database can be opened with the same key
            let exported_db = Database::open(dest_path.to_str().unwrap(), &key).await.unwrap();

            // Read the data from the exported database
            {
                let conn = exported_db.conn().await;
                let mut stmt = conn
                    .prepare("SELECT id, data FROM test_export_data WHERE id = ?1")
                    .unwrap();
                let mut rows = stmt.query([test_id]).unwrap();

                let row = rows.next().unwrap().expect("Expected row to exist");
                let read_id: i32 = row.get(0).unwrap();
                let read_data: Vec<u8> = row.get(1).unwrap();

                assert_eq!(read_id, test_id, "ID should match in exported database");
                assert_eq!(read_data, test_data, "Data should match in exported database");
            }

            // Close databases before cleanup
            drop(db);
            drop(exported_db);

            // temp_dir is automatically cleaned up when it goes out of scope
        });
    }
}
