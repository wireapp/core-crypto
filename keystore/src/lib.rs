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

mod error;
pub use error::*;

#[cfg(feature = "mls-keystore")]
mod mls;

#[cfg(feature = "proteus-keystore")]
mod proteus;

mod migrations {
    refinery::embed_migrations!("src/migrations");
}

#[cfg(feature = "memory-cache")]
const LRU_CACHE_CAP: usize = 100;

#[derive(Debug)]
pub struct CryptoKeystore {
    path: String,
    conn: std::sync::Mutex<rusqlite::Connection>,
    #[cfg(feature = "memory-cache")]
    memory_cache: std::sync::RwLock<lru::LruCache<Vec<u8>, Vec<u8>>>,
    #[cfg(feature = "memory-cache")]
    cache_enabled: std::sync::atomic::AtomicBool,
}

impl CryptoKeystore {
    pub fn open_with_key<P: AsRef<str>, K: AsRef<str>>(path: P, key: K) -> CryptoKeystoreResult<Self> {
        let mut store = Self::init_with_key(path, key)?;
        store.run_migrations()?;

        Ok(store)
    }

    fn init_with_key<P: AsRef<str>, K: AsRef<str>>(path: P, key: K) -> CryptoKeystoreResult<Self> {
        let path = path.as_ref().into();
        let conn = rusqlite::Connection::open(&path)?;

        conn.pragma_update(None, "key", key.as_ref())?;

        // ? iOS WAL journaling fix; see details here: https://github.com/sqlcipher/sqlcipher/issues/255
        #[cfg(feature = "ios-wal-compat")]
        Self::handle_ios_wal_compat(&conn)?;

        // Enable WAL journaling mode
        conn.pragma_update(None, "journal_mode", "wal")?;

        let conn = std::sync::Mutex::new(conn);
        Ok(Self {
            path,
            conn,
            #[cfg(feature = "memory-cache")]
            memory_cache: std::sync::RwLock::new(lru::LruCache::new(LRU_CACHE_CAP)),
            #[cfg(feature = "memory-cache")]
            cache_enabled: true.into(),
        })
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
                hex::decode_to_slice(salt, &mut bytes)?;
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

    pub fn open_in_memory_with_key<K: rusqlite::ToSql>(key: K) -> CryptoKeystoreResult<Self> {
        let conn = rusqlite::Connection::open_in_memory()?;
        conn.pragma_update(None, "key", key)?;

        let conn = std::sync::Mutex::new(conn);
        let mut store = Self {
            path: String::new(),
            conn,
            #[cfg(feature = "memory-cache")]
            memory_cache: std::sync::RwLock::new(lru::LruCache::new(LRU_CACHE_CAP)),
            #[cfg(feature = "memory-cache")]
            cache_enabled: false.into(),
        };

        store.run_migrations()?;

        Ok(store)
    }

    #[cfg(feature = "memory-cache")]
    pub fn cache(&self, enabled: bool) {
        self.cache_enabled.store(enabled, std::sync::atomic::Ordering::SeqCst);
    }

    pub fn run_migrations(&mut self) -> CryptoKeystoreResult<()> {
        migrations::migrations::runner()
            .run(&mut *self.conn.lock().map_err(|_| CryptoKeystoreError::LockPoisonError)?)?;

        Ok(())
    }

    pub fn delete_database_but_please_be_sure(self) -> CryptoKeystoreResult<()> {
        if self.path.is_empty() {
            return Ok(());
        }

        let conn = self
            .conn
            .into_inner()
            .map_err(|_| CryptoKeystoreError::LockPoisonError)?;

        conn.close().map_err(|(_, e)| e)?;

        std::fs::remove_file(&self.path)?;

        Ok(())
    }
}
