mod encryption;
mod filesystem;
#[cfg(target_os = "unknown")]
mod idb_migration;
#[cfg(target_os = "ios")]
mod ios_wal_compat;
mod migrations;
#[cfg(target_os = "unknown")]
mod os_unknown;
mod transaction;

use async_lock::{Mutex, Semaphore};
use rusqlite::Connection;
#[cfg(feature = "log-queries")]
use rusqlite::trace::{TraceEvent, TraceEventCodes};

pub(crate) use self::filesystem::Filesystem;
#[cfg(target_os = "unknown")]
pub use self::idb_migration::legacy_idb_exists;
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
#[derive(Debug, derive_more::Deref, derive_more::DerefMut)]
pub struct Database {
    #[deref]
    #[deref_mut]
    pub(crate) conn: Connection,
    pub(crate) filesystem: Box<dyn Filesystem>,
    pub(crate) transaction: Mutex<Option<KeystoreTransaction>>,
    transaction_semaphore: Semaphore,
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
                encryption::rekey(&mut conn, database_key)?;
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

        // we only actually use the path variable on ios
        #[cfg_attr(not(target_os = "ios"), expect(unused_variables))]
        if let Some(path) = conn.path() {
            // ? iOS WAL journaling fix; see details here: https://github.com/sqlcipher/sqlcipher/issues/255
            #[cfg(target_os = "ios")]
            ios_wal_compat::handle_ios_wal_compat(&conn, path)?;

            // Enable WAL journaling mode when not in memory
            conn.pragma_update(None, "journal_mode", "wal")?;
        }

        migrations::run_migrations(&mut conn, migration_target)?;

        Ok(Self {
            conn,
            filesystem,
            transaction: Default::default(),
            transaction_semaphore: Semaphore::new(ALLOWED_CONCURRENT_TRANSACTIONS_COUNT),
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
    pub async fn open(path: &str, database_key: &DatabaseKey) -> CryptoKeystoreResult<Self> {
        let (conn, filesystem) = Self::open_internal(path, database_key).await?;
        Self::init(conn, filesystem, MigrationTarget::Latest)
    }

    /// Open an in-memory `Database`.
    ///
    /// In-memory databases are never encrypted.
    pub fn open_in_memory() -> CryptoKeystoreResult<Self> {
        let connection = Connection::open_in_memory()?;
        Self::init(connection, Box::new(filesystem::Nop), MigrationTarget::Latest)
    }

    /// Open an encrypted `Database` at the provided location.
    ///
    /// Acts as `open`, but only migrates to the specified schema version.
    #[cfg(all(test, not(target_os = "unknown")))]
    pub(crate) async fn open_at_schema_version(
        path: &str,
        database_key: &DatabaseKey,
        migration_target: MigrationTarget,
    ) -> CryptoKeystoreResult<Self> {
        let (conn, filesystem) = Self::open_internal(path, database_key).await?;
        Self::init(conn, filesystem, migration_target)
    }

    /// Change the database key for this connection.
    pub fn update_key(&mut self, new_key: &DatabaseKey) -> CryptoKeystoreResult<()> {
        encryption::rekey(&mut self.conn, new_key)
    }

    /// Close and remove this database.
    ///
    /// This deletes the database, including its encryption key.
    /// Future opens will always succeed with any arbitrary encryption key; they will
    /// simply open an empty database.
    pub async fn wipe(self) -> CryptoKeystoreResult<()> {
        let location = self.conn.path().map(ToOwned::to_owned);
        self.conn.close().map_err(|(_conn, err)| err)?;
        if let Some(path) = location {
            // not in-memory
            self.filesystem.delete(&path).await?;
        }
        Ok(())
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
        self.conn.execute("VACUUM INTO ?1", [destination_path])?;
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
                db.conn
                    .execute(
                        "CREATE TABLE IF NOT EXISTS test_export_data (id INTEGER PRIMARY KEY, data BLOB)",
                        [],
                    )
                    .unwrap();

                // Insert test data
                db.conn
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
                let mut stmt = exported_db
                    .conn
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
