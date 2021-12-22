mod error;
pub use error::*;
mod mls;
mod proteus;

mod migrations {
    refinery::embed_migrations!("src/migrations");
}

const LRU_CACHE_CAP: usize = 100;

#[derive(Debug)]
pub struct CryptoKeystore {
    conn: std::sync::Mutex<rusqlite::Connection>,
    #[allow(dead_code)]
    // TODO: implement LRU to minimize disk lookups
    memory_cache: lru::LruCache<String, Vec<u8>>,
}

impl CryptoKeystore {
    pub fn open_with_key<S: AsRef<str>>(path: S, key: S) -> error::CryptoKeystoreResult<Self> {
        let conn = rusqlite::Connection::open(path.as_ref())?;
        conn.pragma_update(None, "key", key.as_ref())?;
        let conn = std::sync::Mutex::new(conn);
        Ok(Self {
            conn,
            memory_cache: lru::LruCache::new(LRU_CACHE_CAP),
        })
    }

    #[inline(always)]
    fn key_to_hash<K: std::hash::Hash>(k: &K) -> String {
        use std::hash::Hasher as _;
        let mut s  = std::collections::hash_map::DefaultHasher::new();
        k.hash(&mut s);
        format!("{:X}", s.finish())
    }

    pub fn run_migrations(&mut self) -> error::CryptoKeystoreResult<()> {
        migrations::migrations::runner().run(&mut *self.conn.lock().unwrap())?;
        Ok(())
    }
}
