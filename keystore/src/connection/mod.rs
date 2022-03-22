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

mod platform {
    cfg_if::cfg_if! {
        if #[cfg(target_family = "wasm")] {
            mod wasm;
            pub use self::wasm::WasmConnection as KeystoreDatabaseConnection;
            pub use wasm::storage;
        } else {
            mod generic;
            pub use self::generic::SqlCipherConnection as KeystoreDatabaseConnection;
        }
    }
}

pub use self::platform::*;
use crate::entities::{Entity, StringEntityId};

use crate::{CryptoKeystoreError, CryptoKeystoreResult};
use std::sync::{Mutex, MutexGuard};

#[cfg(feature = "memory-cache")]
const LRU_CACHE_CAP: usize = 100;

pub trait DatabaseConnection: Sized {
    fn open<S: AsRef<str>, S2: AsRef<str>>(name: S, key: S2) -> CryptoKeystoreResult<Self>;

    fn open_in_memory<S: AsRef<str>, S2: AsRef<str>>(name: S, key: S2) -> CryptoKeystoreResult<Self>;

    fn close(self) -> CryptoKeystoreResult<()>;

    /// Default implementation of wipe
    fn wipe(self) -> CryptoKeystoreResult<()> {
        self.close()
    }
}

#[derive(Debug)]
pub struct Connection {
    pub(crate) conn: Mutex<KeystoreDatabaseConnection>,
    #[cfg(feature = "memory-cache")]
    pub(crate) memory_cache: Mutex<lru::LruCache<Vec<u8>, Vec<u8>>>,
    #[cfg(feature = "memory-cache")]
    pub(crate) cache_enabled: std::sync::atomic::AtomicBool,
}

impl Connection {
    pub fn open_with_key(name: impl AsRef<str>, key: impl AsRef<str>) -> CryptoKeystoreResult<Self> {
        let conn = KeystoreDatabaseConnection::open(name, key)?.into();
        Ok(Self {
            conn,
            #[cfg(feature = "memory-cache")]
            memory_cache: lru::LruCache::new(LRU_CACHE_CAP).into(),
            #[cfg(feature = "memory-cache")]
            cache_enabled: true.into(),
        })
    }

    pub fn open_in_memory_with_key(name: impl AsRef<str>, key: impl AsRef<str>) -> CryptoKeystoreResult<Self> {
        let conn = KeystoreDatabaseConnection::open_in_memory(name, key)?.into();
        Ok(Self {
            conn,
            #[cfg(feature = "memory-cache")]
            memory_cache: lru::LruCache::new(LRU_CACHE_CAP).into(),
            #[cfg(feature = "memory-cache")]
            cache_enabled: true.into(),
        })
    }

    pub fn borrow_conn(&self) -> CryptoKeystoreResult<MutexGuard<KeystoreDatabaseConnection>> {
        Ok(self.conn.lock().map_err(|_| CryptoKeystoreError::LockPoisonError)?)
    }

    pub fn insert<E: Entity<ConnectionType = KeystoreDatabaseConnection>>(&self, entity: E) -> CryptoKeystoreResult<E> {
        let mut conn = self.conn.lock().map_err(|_| CryptoKeystoreError::LockPoisonError)?;
        entity.save(&mut *conn)?;
        Ok(entity)
    }

    pub fn find<E: Entity<ConnectionType = KeystoreDatabaseConnection>>(
        &self,
        id: impl AsRef<[u8]>,
    ) -> CryptoKeystoreResult<Option<E>> {
        // TODO: implement support for the memory cache
        // if self.is_cache_enabled() {
        //     if let Some(cached) = self
        //         .memory_cache
        //         .lock()
        //         .map_err(|_| CryptoKeystoreError::LockPoisonError)?
        //         .get(id.as_ref())
        //     {
        //         return cached;
        //     }
        // }
        let mut conn = self.conn.lock().map_err(|_| CryptoKeystoreError::LockPoisonError)?;
        E::find_one(&mut *conn, &id.as_ref().into())
    }

    pub fn find_many<E: Entity<ConnectionType = KeystoreDatabaseConnection>, S: AsRef<[u8]>>(
        &self,
        ids: &[S],
    ) -> CryptoKeystoreResult<Vec<E>> {
        let mut conn = self.conn.lock().map_err(|_| CryptoKeystoreError::LockPoisonError)?;
        E::find_many(
            &mut *conn,
            &ids.iter().map(|id| id.as_ref().into()).collect::<Vec<StringEntityId>>(),
        )
    }

    pub fn remove<E: Entity<ConnectionType = KeystoreDatabaseConnection>, S: AsRef<[u8]>>(
        &self,
        id: S,
    ) -> CryptoKeystoreResult<()> {
        let mut conn = self.conn.lock().map_err(|_| CryptoKeystoreError::LockPoisonError)?;
        E::delete(&mut *conn, &id.as_ref().into())
    }

    pub fn count<E: Entity<ConnectionType = KeystoreDatabaseConnection>>(&self) -> CryptoKeystoreResult<usize> {
        let mut conn = self.conn.lock().map_err(|_| CryptoKeystoreError::LockPoisonError)?;
        E::count(&mut *conn)
    }

    pub fn wipe(self) -> CryptoKeystoreResult<()> {
        let conn = self
            .conn
            .into_inner()
            .map_err(|_| CryptoKeystoreError::LockPoisonError)?;

        conn.wipe()
    }

    #[cfg(feature = "memory-cache")]
    #[inline]
    pub fn cache(&self, enabled: bool) {
        self.cache_enabled.store(enabled, std::sync::atomic::Ordering::SeqCst);
    }

    #[cfg(feature = "memory-cache")]
    #[inline]
    pub fn is_cache_enabled(&self) -> bool {
        self.cache_enabled.load(std::sync::atomic::Ordering::Relaxed)
    }
}
