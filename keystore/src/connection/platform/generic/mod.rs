// Wire
// Copyright (C) 2022 Wire Swiss GmbH

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with this program. If not, see http://www.gnu.org/licenses/.

use std::ops::Deref;

use crate::CryptoKeystoreResult;
use crate::connection::{DatabaseConnection, DatabaseConnectionRequirements};
use async_lock::{Mutex, MutexGuard};
use blocking::unblock;
use rusqlite::{Transaction, functions::FunctionFlags};

#[cfg(feature = "ios-wal-compat")]
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
    fn init_with_key(path: &str, key: &str) -> CryptoKeystoreResult<Self> {
        #[allow(unused_mut)]
        let mut conn = rusqlite::Connection::open(path)?;
        cfg_if::cfg_if! {
            if #[cfg(feature = "log-queries")] {
                fn log_query(q: &str) {
                    log::info!("{}", q);
                }

                conn.trace(Some(log_query));
            }
        }

        conn.pragma_update(None, "key", key)?;

        // ? iOS WAL journaling fix; see details here: https://github.com/sqlcipher/sqlcipher/issues/255
        #[cfg(feature = "ios-wal-compat")]
        ios_wal_compat::handle_ios_wal_compat(&conn, path)?;

        // Enable WAL journaling mode
        conn.pragma_update(None, "journal_mode", "wal")?;

        // Disable FOREIGN KEYs - The 2 step blob writing process invalidates foreign key checks unfortunately
        conn.pragma_update(None, "foreign_keys", "OFF")?;

        let conn = Mutex::new(conn);

        let mut conn = Self {
            path: path.into(),
            conn,
        };
        conn.run_migrations()?;

        Ok(conn)
    }

    fn init_with_key_in_memory(_path: &str, key: &str) -> CryptoKeystoreResult<Self> {
        #[allow(unused_mut)]
        let mut conn = rusqlite::Connection::open("")?;
        cfg_if::cfg_if! {
            if #[cfg(feature = "log-queries")] {
                fn log_query(q: &str) {
                    log::info!("{}", q);
                }

                conn.trace(Some(log_query));
            }
        }
        conn.pragma_update(None, "key", key)?;

        // Disable FOREIGN KEYs - The 2 step blob writing process invalidates foreign key checks unfortunately
        conn.pragma_update(None, "foreign_keys", "OFF")?;

        let conn = Mutex::new(conn);

        let mut conn = Self { path: "".into(), conn };

        // Need to run migrations also in memory to make sure expected tables exist.
        conn.run_migrations()?;

        Ok(conn)
    }

    pub async fn conn(&self) -> MutexGuard<rusqlite::Connection> {
        self.conn.lock().await
    }

    pub fn conn_blocking(&self) -> MutexGuard<rusqlite::Connection> {
        self.conn.lock_blocking()
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

    fn run_migrations(&mut self) -> CryptoKeystoreResult<()> {
        let mut conn = self.conn_blocking();
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

    async fn open(name: &str, key: &str) -> CryptoKeystoreResult<Self> {
        let name = name.to_string();
        let key = key.to_string();
        Ok(unblock(move || Self::init_with_key(&name, &key)).await?)
    }

    async fn open_in_memory(name: &str, key: &str) -> CryptoKeystoreResult<Self> {
        let name = name.to_string();
        let key = key.to_string();
        Ok(unblock(move || Self::init_with_key_in_memory(&name, &key)).await?)
    }

    async fn close(self) -> CryptoKeystoreResult<()> {
        unblock(|| self.close()).await
    }

    async fn wipe(self) -> CryptoKeystoreResult<()> {
        self.wipe().await?;
        Ok(())
    }
}
