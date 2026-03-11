mod encryption;
#[cfg(target_os = "ios")]
mod ios_wal_compat;
mod migrations;
#[cfg(target_os = "unknown")]
mod os_unknown;

use std::{
    ops::{Deref, DerefMut},
    sync::Arc,
};

use async_lock::{Mutex, Semaphore};
#[cfg(feature = "log-queries")]
use rusqlite::trace::{TraceEvent, TraceEventCodes};

pub use self::migrations::migrate_db_key_type_to_bytes;
use crate::{CryptoKeystoreResult, DatabaseKey, transaction::KeystoreTransaction};

const ALLOWED_CONCURRENT_TRANSACTIONS_COUNT: usize = 1;

#[cfg(feature = "log-queries")]
fn log_query(event: TraceEvent) {
    if let TraceEvent::Stmt(_, sql) = event {
        log::info!("{sql}")
    }
}

/// This connection wrapper exists so that we have an equivalent so `dyn RusqliteConnection`
/// works on nearly-bare connections.
#[derive(derive_more::Debug, derive_more::Deref, derive_more::DerefMut)]
#[debug("{_0:?}")]
struct ConnectionWrapper(rusqlite::Connection);

/// This trait exists so we can use a bare [`rusqlite::Connection`] instance when in memory.
pub(crate) trait RusqliteConnection:
    'static + Deref<Target = rusqlite::Connection> + DerefMut + std::fmt::Debug
{
}
impl<T> RusqliteConnection for T where T: 'static + Deref<Target = rusqlite::Connection> + DerefMut + std::fmt::Debug {}

#[derive(Debug, Clone)]
pub struct Database {
    pub(crate) conn: Arc<dyn RusqliteConnection>,
    pub(crate) transaction: Arc<Mutex<Option<KeystoreTransaction>>>,
    transaction_semaphore: Arc<Semaphore>,
}

impl Database {
    /// Set up the database from a connection
    ///
    /// The connection must already be configured for encryption if appropriate.
    ///
    /// Sets appropriate pragmas and performs migrations and general initialization work.
    fn init(mut conn: impl RusqliteConnection) -> CryptoKeystoreResult<Self> {
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

        let conn = Arc::new(conn);
        Ok(Self {
            conn,
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
    pub async fn open(path: &str, database_key: &DatabaseKey) -> CryptoKeystoreResult<Self> {
        #[cfg(target_os = "unknown")]
        let connection = { os_unknown::Connection::open(path, database_key).await? };

        #[cfg(not(target_os = "unknown"))]
        let connection = {
            let exists = std::fs::exists(path)?;
            let mut connection = rusqlite::Connection::open(path)?;
            if exists {
                encryption::decrypt(&mut connection, database_key)?;
            } else {
                encryption::rekey(&mut connection, database_key)?;
            }
            ConnectionWrapper(connection)
        };

        Self::init(connection)
    }

    /// Open an in-memory `Database`.
    ///
    /// In-memory databases are never encrypted.
    pub fn open_in_memory() -> CryptoKeystoreResult<Self> {
        let connection = rusqlite::Connection::open_in_memory()?;
        Self::init(ConnectionWrapper(connection))
    }
}
