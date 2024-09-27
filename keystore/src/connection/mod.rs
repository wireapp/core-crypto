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

pub mod platform {
    cfg_if::cfg_if! {
        if #[cfg(target_family = "wasm")] {
            mod wasm;
            pub use self::wasm::WasmConnection as KeystoreDatabaseConnection;
            pub use wasm::storage;
            pub use self::wasm::storage::WasmStorageTransaction as TransactionWrapper;
        } else {
            mod generic;
            pub use self::generic::SqlCipherConnection as KeystoreDatabaseConnection;
            pub use self::generic::TransactionWrapper;
        }
    }
}

pub use self::platform::*;
use crate::{
    entities::{Entity, EntityFindParams, StringEntityId},
    KeystoreTransaction,
};

use crate::entities::UniqueEntity;
use crate::{CryptoKeystoreError, CryptoKeystoreResult};
use async_lock::{Mutex, MutexGuard};
use std::sync::Arc;

/// Limit on the length of a blob to be stored in the database.
///
/// This limit applies to both SQLCipher-backed stores and WASM.
/// This limit is conservative on purpose when targeting WASM, as the lower bound that exists is Safari with a limit of 1GB per origin.
///
/// See: [SQLite limits](https://www.sqlite.org/limits.html)
/// See: [IndexedDB limits](https://stackoverflow.com/a/63019999/1934177)
pub const MAX_BLOB_LEN: usize = 1_000_000_000;

#[cfg(not(target_family = "wasm"))]
// ? Because of UniFFI async requirements, we need our keystore to be Send as well now
pub trait DatabaseConnectionRequirements: Sized + Send {}
#[cfg(target_family = "wasm")]
// ? On the other hand, things cannot be Send on WASM because of platform restrictions (all things are copied across the FFI)
pub trait DatabaseConnectionRequirements: Sized {}

#[cfg_attr(target_family = "wasm", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_family = "wasm"), async_trait::async_trait)]
pub trait DatabaseConnection: DatabaseConnectionRequirements {
    async fn open(name: &str, key: &str) -> CryptoKeystoreResult<Self>;

    async fn open_in_memory(name: &str, key: &str) -> CryptoKeystoreResult<Self>;

    async fn close(self) -> CryptoKeystoreResult<()>;

    /// Default implementation of wipe
    async fn wipe(self) -> CryptoKeystoreResult<()> {
        self.close().await
    }

    fn check_buffer_size(size: usize) -> CryptoKeystoreResult<()> {
        #[cfg(not(target_family = "wasm"))]
        if size > i32::MAX as usize {
            return Err(CryptoKeystoreError::BlobTooBig);
        }

        if size >= MAX_BLOB_LEN {
            return Err(CryptoKeystoreError::BlobTooBig);
        }

        Ok(())
    }
    #[cfg(not(target_family = "wasm"))]
    async fn new_transaction(&mut self) -> CryptoKeystoreResult<TransactionWrapper<'_>>;
    #[cfg(target_family = "wasm")]
    async fn new_transaction<T: AsRef<str>>(
        &mut self,
        tables: &[T],
    ) -> CryptoKeystoreResult<crate::connection::TransactionWrapper<'_>>;
}

#[derive(Debug, Clone)]
pub struct Connection {
    pub(crate) conn: Arc<Mutex<KeystoreDatabaseConnection>>,
}

/// Interface to fetch from the database either from the connection directly or through a
/// transaaction
#[cfg_attr(target_family = "wasm", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_family = "wasm"), async_trait::async_trait)]
pub trait FetchFromDatabase: Send + Sync {
    async fn find<E: Entity<ConnectionType = KeystoreDatabaseConnection>>(
        &self,
        id: &[u8],
    ) -> CryptoKeystoreResult<Option<E>>;

    async fn find_unique<U: UniqueEntity<ConnectionType = KeystoreDatabaseConnection>>(
        &self,
    ) -> CryptoKeystoreResult<U>;

    async fn find_all<E: Entity<ConnectionType = KeystoreDatabaseConnection>>(
        &self,
        params: EntityFindParams,
    ) -> CryptoKeystoreResult<Vec<E>>;

    async fn find_many<E: Entity<ConnectionType = KeystoreDatabaseConnection>>(
        &self,
        ids: &[Vec<u8>],
    ) -> CryptoKeystoreResult<Vec<E>>;
    async fn count<E: Entity<ConnectionType = KeystoreDatabaseConnection>>(&self) -> CryptoKeystoreResult<usize>;
}

// * SAFETY: this has mutexes and atomics protecting underlying data so this is safe to share between threads
unsafe impl Send for Connection {}
unsafe impl Sync for Connection {}

impl Connection {
    pub async fn open_with_key(name: impl AsRef<str>, key: impl AsRef<str>) -> CryptoKeystoreResult<Self> {
        let conn = KeystoreDatabaseConnection::open(name.as_ref(), key.as_ref())
            .await?
            .into();
        #[allow(clippy::arc_with_non_send_sync)] // see https://github.com/rustwasm/wasm-bindgen/pull/955
        let conn = Arc::new(conn);
        Ok(Self { conn })
    }

    pub async fn open_in_memory_with_key(name: impl AsRef<str>, key: impl AsRef<str>) -> CryptoKeystoreResult<Self> {
        let conn = KeystoreDatabaseConnection::open_in_memory(name.as_ref(), key.as_ref())
            .await?
            .into();
        #[allow(clippy::arc_with_non_send_sync)] // see https://github.com/rustwasm/wasm-bindgen/pull/955
        let conn = Arc::new(conn);
        Ok(Self { conn })
    }

    pub async fn borrow_conn(&self) -> CryptoKeystoreResult<MutexGuard<'_, KeystoreDatabaseConnection>> {
        Ok(self.conn.lock().await)
    }

    // TODO: only allow this for proteus for now
    pub async fn save<E: Entity<ConnectionType = KeystoreDatabaseConnection> + std::marker::Sync>(
        &self,
        entity: E,
    ) -> CryptoKeystoreResult<E> {
        let mut conn = self.conn.lock().await;
        entity.save(&mut conn).await?;
        Ok(entity)
    }

    // TODO: only allow this for proteus for now
    pub async fn insert<E: Entity<ConnectionType = KeystoreDatabaseConnection> + std::marker::Sync>(
        &self,
        entity: E,
    ) -> CryptoKeystoreResult<E::AutoGeneratedFields> {
        let mut conn = self.conn.lock().await;
        let fields = entity.insert(&mut conn).await?;
        Ok(fields)
    }

    // TODO: only allow this for proteus for now
    pub async fn remove<E: Entity<ConnectionType = KeystoreDatabaseConnection>, S: AsRef<[u8]>>(
        &self,
        id: S,
    ) -> CryptoKeystoreResult<()> {
        let mut conn = self.conn.lock().await;
        E::delete(&mut conn, id.as_ref().into()).await?;
        Ok(())
    }

    pub async fn wipe(self) -> CryptoKeystoreResult<()> {
        let conn: KeystoreDatabaseConnection = Arc::try_unwrap(self.conn).unwrap().into_inner();

        conn.wipe().await?;
        Ok(())
    }

    pub async fn close(self) -> CryptoKeystoreResult<()> {
        let conn: KeystoreDatabaseConnection = Arc::try_unwrap(self.conn).unwrap().into_inner();
        conn.close().await?;
        Ok(())
    }

    pub fn new_transaction(&self) -> KeystoreTransaction {
        KeystoreTransaction::new(self.clone())
    }
}

#[cfg_attr(target_family = "wasm", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_family = "wasm"), async_trait::async_trait)]
impl FetchFromDatabase for Connection {
    async fn find<E: Entity<ConnectionType = KeystoreDatabaseConnection>>(
        &self,
        id: &[u8],
    ) -> CryptoKeystoreResult<Option<E>> {
        let mut conn = self.conn.lock().await;
        E::find_one(&mut conn, &id.into()).await
    }

    async fn find_unique<U: UniqueEntity>(&self) -> CryptoKeystoreResult<U> {
        let mut conn = self.conn.lock().await;
        U::find_unique(&mut conn).await
    }

    async fn find_all<E: Entity<ConnectionType = KeystoreDatabaseConnection>>(
        &self,
        params: EntityFindParams,
    ) -> CryptoKeystoreResult<Vec<E>> {
        let mut conn = self.conn.lock().await;
        E::find_all(&mut conn, params).await
    }

    async fn find_many<E: Entity<ConnectionType = KeystoreDatabaseConnection>>(
        &self,
        ids: &[Vec<u8>],
    ) -> CryptoKeystoreResult<Vec<E>> {
        let entity_ids: Vec<StringEntityId> = ids.iter().map(|id| id.as_slice().into()).collect();
        let mut conn = self.conn.lock().await;
        E::find_many(&mut conn, &entity_ids).await
    }

    async fn count<E: Entity<ConnectionType = KeystoreDatabaseConnection>>(&self) -> CryptoKeystoreResult<usize> {
        let mut conn = self.conn.lock().await;
        E::count(&mut conn).await
    }
}
