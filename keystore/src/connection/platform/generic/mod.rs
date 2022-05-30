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

use crate::connection::DatabaseConnection;
use crate::CryptoKeystoreResult;

refinery::embed_migrations!("src/connection/platform/generic/migrations");

#[derive(Debug)]
pub struct SqlCipherConnection {
    conn: rusqlite::Connection,
    path: String,
}

impl std::ops::Deref for SqlCipherConnection {
    type Target = rusqlite::Connection;

    fn deref(&self) -> &Self::Target {
        &self.conn
    }
}

impl std::ops::DerefMut for SqlCipherConnection {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.conn
    }
}

impl SqlCipherConnection {
    fn init_with_connection(conn: rusqlite::Connection, path: &str, key: &str) -> CryptoKeystoreResult<Self> {
        conn.pragma_update(None, "key", key)?;

        // ? iOS WAL journaling fix; see details here: https://github.com/sqlcipher/sqlcipher/issues/255
        #[cfg(feature = "ios-wal-compat")]
        Self::handle_ios_wal_compat(&conn)?;

        // Enable WAL journaling mode
        conn.pragma_update(None, "journal_mode", "wal")?;

        let mut conn = Self {
            path: path.into(),
            conn,
        };
        conn.run_migrations()?;

        Ok(conn)
    }

    fn init_with_key(path: impl AsRef<str>, key: impl AsRef<str>) -> CryptoKeystoreResult<Self> {
        let conn = rusqlite::Connection::open(path.as_ref())?;
        Self::init_with_connection(conn, path.as_ref(), key.as_ref())
    }

    fn init_with_key_in_memory(path: impl AsRef<str>, key: impl AsRef<str>) -> CryptoKeystoreResult<Self> {
        let conn = rusqlite::Connection::open_in_memory()?;
        Self::init_with_connection(conn, path.as_ref(), key.as_ref())
    }

    pub fn wipe(self) -> CryptoKeystoreResult<()> {
        if self.path.is_empty() {
            return Ok(());
        }

        self.conn.close().map_err(|(_, e)| e)?;
        std::fs::remove_file(&self.path)?;
        Ok(())
    }

    /// To prevent iOS from killing backgrounded apps using a WAL-journaled file,
    /// we need to leave the first 32 bytes as plaintext, this way, iOS can see the
    /// `SQLite Format 3\0` magic bytes and identify the file as a SQLite database
    /// and when it does so, it treats this file "specially" and avoids killing the app
    /// when doing background work
    /// See more: https://github.com/sqlcipher/sqlcipher/issues/255
    #[cfg(feature = "ios-wal-compat")]
    fn handle_ios_wal_compat(conn: &rusqlite::Connection) -> CryptoKeystoreResult<()> {
        const ERR_SEC_ITEM_NOT_FOUND: i32 = -25300;
        match security_framework::passwords::get_generic_password("wire.com", "keystore_salt") {
            Ok(salt) => {
                conn.pragma_update(None, "cipher_salt", format!("x'{}'", hex::encode(salt)))?;
            }
            Err(e) if e.code() == ERR_SEC_ITEM_NOT_FOUND => {
                let salt = conn.pragma_query_value(None, "cipher_salt", |r| r.get::<_, String>(0))?;
                let mut bytes = [0u8; 16];
                hex::decode_to_slice(salt, &mut bytes)
                    .map_err(|e| crate::CryptoKeystoreError::HexSaltDecodeError(e))?;
                #[cfg(target_os = "ios")]
                security_framework::password::set_generic_password("wire.com", "keystore_salt", bytes)?;
            }
            Err(e) => return Err(e.into()),
        }

        const CIPHER_PLAINTEXT_BYTES: u32 = 32;
        conn.pragma_update(None, "cipher_plaintext_header_size", CIPHER_PLAINTEXT_BYTES)?;
        conn.pragma_update(None, "user_version", 1u32)?;

        Ok(())
    }

    fn run_migrations(&mut self) -> CryptoKeystoreResult<()> {
        migrations::runner().run(&mut self.conn)?;

        Ok(())
    }
}

impl DatabaseConnection for SqlCipherConnection {
    fn open<S: AsRef<str>, S2: AsRef<str>>(name: S, key: S2) -> CryptoKeystoreResult<Self> {
        Self::init_with_key(name, key)
    }

    fn open_in_memory<S: AsRef<str>, S2: AsRef<str>>(name: S, key: S2) -> CryptoKeystoreResult<Self> {
        Self::init_with_key_in_memory(name, key)
    }

    fn close(self) -> CryptoKeystoreResult<()> {
        Ok(self.conn.close().map_err(|(_, e)| e)?)
    }

    fn wipe(self) -> CryptoKeystoreResult<()> {
        self.wipe()
    }
}
