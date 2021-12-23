mod error;
pub use error::*;
mod mls;
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
    pub fn open_with_key<P: AsRef<str>, K: rusqlite::ToSql>(
        path: P,
        key: K,
    ) -> error::CryptoKeystoreResult<Self> {
        let mut store = Self::init_with_key(path, key)?;
        store.run_migrations()?;
        Ok(store)
    }

    fn init_with_key<P: AsRef<str>, K: rusqlite::ToSql>(
        path: P,
        key: K,
    ) -> error::CryptoKeystoreResult<Self> {
        let path = path.as_ref().into();
        let conn = rusqlite::Connection::open(&path)?;
        conn.pragma_update(None, "key", key)?;
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

    #[cfg(feature = "memory-cache")]
    pub fn cache(&self, enabled: bool) {
        self.cache_enabled
            .store(enabled, std::sync::atomic::Ordering::SeqCst);
    }

    #[inline]
    fn key_to_hash<K: std::hash::Hash>(k: &K) -> String {
        use std::hash::Hasher as _;
        let mut s = std::collections::hash_map::DefaultHasher::new();
        k.hash(&mut s);
        format!("{:X}", s.finish())
    }

    pub fn run_migrations(&mut self) -> error::CryptoKeystoreResult<()> {
        migrations::migrations::runner().run(
            &mut *self
                .conn
                .lock()
                .map_err(|_| CryptoKeystoreError::LockPoisonError)?,
        )?;
        Ok(())
    }

    pub fn delete_database_but_please_be_sure(self) -> error::CryptoKeystoreResult<()> {
        let conn = self
            .conn
            .into_inner()
            .map_err(|_| error::CryptoKeystoreError::LockPoisonError)?;
        conn.close().map_err(|(_, e)| e)?;
        std::fs::remove_file(&self.path)?;
        Ok(())
    }
}
