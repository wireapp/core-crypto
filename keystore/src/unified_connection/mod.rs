mod encryption;
mod fs_abstraction;
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

pub(crate) use self::fs_abstraction::FilesystemAbstraction;
pub use self::migrations::migrate_db_key_type_to_bytes;
use crate::{CryptoKeystoreResult, DatabaseKey, transaction::KeystoreTransaction};

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
    pub(crate) conn: Connection,
    pub(crate) fs_abstraction: Box<dyn FilesystemAbstraction>,
    pub(crate) transaction: Mutex<Option<KeystoreTransaction>>,
    transaction_semaphore: Semaphore,
}

impl Database {
    /// Set up the database from a connection
    ///
    /// The connection must already be configured for encryption if appropriate.
    ///
    /// Sets appropriate pragmas and performs migrations and general initialization work.
    fn init(mut conn: Connection, fs_abstraction: Box<dyn FilesystemAbstraction>) -> CryptoKeystoreResult<Self> {
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

        migrations::run_migrations(&mut conn, Default::default())?;

        Ok(Self {
            conn,
            fs_abstraction,
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
        #[cfg(target_os = "unknown")]
        let (conn, fs_abstraction) = { os_unknown::open(path, database_key).await? };

        #[cfg(not(target_os = "unknown"))]
        let (conn, fs_abstraction) = {
            let exists = std::fs::exists(path)?;
            let mut conn = Connection::open(path)?;
            if exists {
                encryption::decrypt(&mut conn, database_key)?;
            } else {
                encryption::rekey(&mut conn, database_key)?;
            }
            (conn, fs_abstraction::NativeFs)
        };

        let fs_abstraction = Box::new(fs_abstraction);
        Self::init(conn, fs_abstraction)
    }

    /// Open an in-memory `Database`.
    ///
    /// In-memory databases are never encrypted.
    pub fn open_in_memory() -> CryptoKeystoreResult<Self> {
        let connection = Connection::open_in_memory()?;
        Self::init(connection, Box::new(fs_abstraction::Nop))
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
            self.fs_abstraction.delete(&path).await?;
        }
        Ok(())
    }
}
