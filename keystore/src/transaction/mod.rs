mod conn;
mod fetch_from_database;
mod finalize;
mod mls;
#[cfg(feature = "proteus-keystore")]
mod proteus;
mod savepoint;

use std::sync::Arc;

use async_lock::MutexGuardArc;
use parking_lot::Mutex;
use rusqlite::Connection;

pub(crate) use self::{conn::TransactionConnection, mls::read_mls_entity};
use crate::{CryptoKeystoreResult, Database, UniqueArc, connection::TransactionGuard, entities::InboxMessage};

const GUARD_EXPECTATION: &str = "connection guard is present for the lifetime of the transaction wrapper";

/// This is a guard over an in-flight transaction.
///
/// In a perfect world we'd be able to use [`rusqlite::Transaction`], but that type
/// is intentionally `!Send + !Sync`, which prevents us from being able to keep a
/// long-lived transaction around.
///
/// Dropping the transaction without committing performs an implicit rollback.
///
/// This type is always wrapped in a [`UniqueArc`], which keeps things efficient,
/// at the cost of prohibiting `Clone`. In case you need to share this around,
/// there are weak references available via [`UniqueArc::downgrade`].
/// Alternately, wrap the entire thing in an `Arc<Mutex<Option<UniqueArc<Self>>>>` or similar.
/// Just be aware that you'll need to take the unique arc out in order to commit.
pub struct Transaction {
    /// The lock guard is never used directly, but is held to ensure that only one transaction
    /// is ever live simultaneously. Sqlite already gives us that protection, but we can `.await`
    /// the transaction guard instead of just catching the error if we try to double-up.
    _lock_guard: TransactionGuard,
    /// The database reference is kept only to invalidate the weak pointer when this transaction
    /// is either committed or rolled back.
    ///
    /// **IMPORTANT**: do not attempt to take `self.database.conn().await`. THIS WILL DEADLOCK.
    /// Use `self.conn` instead.
    ///
    /// We have to hold a separate long-lived lock to the database's internal connection because
    /// the mutex guarding it is async, but we depend on non-async `Drop` behavior.
    database: Arc<Database>,
    /// Guard over the actual database connection. We have to hold this for the entire lifetime
    /// of this transaction. That's a bit selfish on one hand, because it opens the door to
    /// potential deadlocks if we write things wrong. On the other hand it is required because
    /// our `Drop` impl would otherwise need to asynchronously lock the database to get the connection,
    /// and async `Drop` is not yet a thing.
    ///
    /// The `Option` ensures we can safely invalidate this transaction after commit and rollback.
    /// Can't mess with the database after either of those!
    ///
    /// The synchronous Mutex here does a few things:
    ///
    /// - turns `Connection: Send + !Sync` -> `Transaction: Send + Sync`
    /// - by using the synchronous version, the compiler ensures we don't hold a guard over an await point, which would
    ///   deadlock everything
    /// - ensures that no two threads race on `conn.prepare` / `prepare_cached`
    ///
    /// On Wasm, callers acquire `SqliteGuard` before this mutex: JSPI can suspend
    /// a synchronous SQLite call while it holds the mutex.
    conn: Arc<parking_lot::Mutex<Option<MutexGuardArc<crate::connection::ManagedConnection>>>>,
    /// The current max arrival sequence of any inbox message.
    ///
    /// This transaction may feel like an odd place to store this, given that an inbox message is an
    /// entity and its arrival sequence is more like business logic than like database management.
    ///
    /// The argument is that the transaction is the correct place to store it because it holds an exclusive
    /// lock over the database: while a transaction is live, no other task or process can insert new
    /// inbox messages, except via this transaction. So storing the arrival sequence here works.
    inbox_message_max_arrival_sequence: Mutex<u64>,
}

impl Transaction {
    /// Instantiate a new transaction.
    ///
    /// Requires a transaction lock guard to ensure that only one exists at a time.
    pub(crate) async fn new(
        lock_guard: TransactionGuard,
        database: Arc<Database>,
    ) -> CryptoKeystoreResult<UniqueArc<Self>> {
        let conn = database.raw_conn().await;

        {
            let _sqlite = crate::connection::SqliteGuard::lock();
            // initialize the DB-level transaction before doing any construction work on the type-level
            // transaction; failure here invalidates everything to follow. We don't need to worry about
            // concurrency; we already hold the lock guard.
            let mut stmt = conn.prepare_cached("BEGIN IMMEDIATE TRANSACTION")?;
            stmt.execute([])?;
        }

        let inbox_message_max_arrival_sequence = InboxMessage::max_arrival_sequence(&conn)?.into();

        let transaction = UniqueArc::from(Self {
            _lock_guard: lock_guard,
            database,
            conn: Arc::new(parking_lot::Mutex::new(Some(conn))),
            inbox_message_max_arrival_sequence,
        });

        let weak = UniqueArc::downgrade(&transaction);

        {
            let mut transaction_guard = transaction.database.transaction.lock().await;
            // this transaction guard may be `None` if the database is new or the previous transaction
            // was committed.
            // it may be `Some(_)` if the previous transaction was rolled back by means of dropping the
            // `UniqueArc<Transaction>`. either way, it's correct to simply replace it without checking the
            // previous value.
            *transaction_guard = Some(weak);
        }

        Ok(transaction)
    }

    /// `true` when the transaction is active.
    ///
    /// You'd think that given the presence of this wrapper, you could assume that a transaction
    /// is active: instantiating one creates a transaction, and the consuming methods close it.
    /// However, Sqlite can sometimes automatically roll back transactions without telling the
    /// user:
    ///
    /// <https://sqlite.org/c3ref/get_autocommit.html>
    ///
    /// > The only way to find out whether SQLite automatically rolled back the transaction
    /// > after an error is to use this function.
    fn is_active(conn: &Connection) -> bool {
        !conn.is_autocommit()
    }

    /// Get the next arrival sequence number for an inbox message.
    ///
    /// Multiple calls will return increasing integers. It's fine if any given conversation
    /// has gaps between messages; only the relative ordering matters.
    ///
    /// Not idempotent, but the u64 space is big enough that it shouldn't matter.
    pub fn inbox_message_next_arrival_sequence(&self) -> u64 {
        let mut guard = self.inbox_message_max_arrival_sequence.lock();
        *guard += 1;
        *guard
    }
}
