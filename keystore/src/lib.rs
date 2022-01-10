mod error;
pub use error::*;
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
    memory_cache: std::sync::RwLock<lru::LruCache<String, Vec<u8>>>,
    #[cfg(feature = "memory-cache")]
    cache_enabled: std::sync::atomic::AtomicBool,
}

impl CryptoKeystore {
    pub fn open_with_key<P: AsRef<str>, K: AsRef<str>>(path: P, key: K) -> error::CryptoKeystoreResult<Self> {
        let mut store = Self::init_with_key(path, key)?;
        store.run_migrations()?;
        Ok(store)
    }

    fn init_with_key<P: AsRef<str>, K: AsRef<str>>(path: P, key: K) -> error::CryptoKeystoreResult<Self> {
        let path = path.as_ref().into();
        let conn = rusqlite::Connection::open(&path)?;

        conn.pragma_update(None, "key", key.as_ref())?;

        // ? iOS WAL journaling fix; see details here: https://github.com/sqlcipher/sqlcipher/issues/255
        #[cfg(feature = "ios-wal-compat")]
        Self::handle_ios_wal_compat(&conn)?; //, &path, key)?;

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
    fn handle_ios_wal_compat(
        conn: &rusqlite::Connection,
        // db_path: &String,
        // key: K,
    ) -> CryptoKeystoreResult<()> {
        const ERR_SEC_ITEM_NOT_FOUND: i32 = -25300;
        match security_framework::passwords::get_generic_password("wire.com", "keystore_salt") {
            Ok(salt) => {
                conn.pragma_update(None, "cipher_salt", format!("x'{}'", hex::encode(salt)))?;
            }
            Err(e) if e.code() == ERR_SEC_ITEM_NOT_FOUND => {
                let salt = conn.pragma_query_value(None, "cipher_salt", |r| r.get::<_, String>(0))?;
                let mut bytes = [0u8; 16];
                hex::decode_to_slice(salt, &mut bytes)?;
                security_framework::password::set_generic_password("wire.com", "keystore_salt", bytes)?;
            }
            Err(e) => return Err(e.into()),
        }
        // TODO: Refactor this and store the salt in the iOS keychain instead
        // use aes::{BlockDecrypt as _, BlockEncrypt as _, NewBlockCipher as _};
        // use std::io::Read as _;

        const CIPHER_PLAINTEXT_BYTES: u32 = 32;
        // let mut cipher_key = [0u8; 32];
        // cipher_key[..std::cmp::min(key.as_ref().len(), 32)].copy_from_slice(key.as_ref().as_bytes());
        // let cipher = aes::Aes256::new(&cipher_key.into());

        // let salt_path = std::path::Path::new(db_path).with_extension("edb-salt");
        // if salt_path.is_file() {
        //     let mut salt_file = std::fs::File::open(salt_path)?;
        //     let mut buf = [0u8; 16];
        //     salt_file.read_exact(&mut buf)?;
        //     cipher.decrypt_block(aes::Block::from_mut_slice(&mut buf));
        //     conn.pragma_update(None, "cipher_salt", format!("x'{}'", hex::encode(buf)))?;
        // } else {
        //     let salt = conn.pragma_query_value(None, "cipher_salt", |r| r.get::<_, String>(0))?;
        //     let mut bytes = [0u8; 16];
        //     hex::decode_to_slice(salt, &mut bytes)?;
        //     cipher.encrypt_block(aes::Block::from_mut_slice(&mut bytes));
        //     std::fs::write(salt_path, bytes.as_slice())?;
        // }

        conn.pragma_update(None, "cipher_plaintext_header_size", CIPHER_PLAINTEXT_BYTES)?;
        conn.pragma_update(None, "user_version", 1)?;

        Ok(())
    }

    pub fn open_in_memory_with_key<K: rusqlite::ToSql>(key: K) -> error::CryptoKeystoreResult<Self> {
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

    #[inline]
    fn key_to_hash<K: std::hash::Hash>(k: &K) -> String {
        use std::hash::Hasher as _;
        let mut s = std::collections::hash_map::DefaultHasher::new();
        k.hash(&mut s);
        format!("{:X}", s.finish())
    }

    pub fn run_migrations(&mut self) -> error::CryptoKeystoreResult<()> {
        migrations::migrations::runner()
            .run(&mut *self.conn.lock().map_err(|_| CryptoKeystoreError::LockPoisonError)?)?;
        Ok(())
    }

    pub fn delete_database_but_please_be_sure(self) -> error::CryptoKeystoreResult<()> {
        if self.path.is_empty() {
            return Ok(());
        }

        let conn = self
            .conn
            .into_inner()
            .map_err(|_| error::CryptoKeystoreError::LockPoisonError)?;
        conn.close().map_err(|(_, e)| e)?;
        std::fs::remove_file(&self.path)?;
        Ok(())
    }
}
