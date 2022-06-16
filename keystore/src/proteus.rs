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

use rusqlite::OptionalExtension as _;

use crate::{
    connection::Connection, entities::ProteusPrekey, CryptoKeystoreError, CryptoKeystoreResult, MissingKeyErrorKind,
};

#[async_trait::async_trait(?Send)]
pub trait CryptoKeystoreProteus {
    async fn store_prekey(&self, prekey: &proteus::keys::PreKey) -> CryptoKeystoreResult<()>;
}

#[async_trait::async_trait(?Send)]
impl CryptoKeystoreProteus for Connection {
    async fn store_prekey(&self, prekey: &proteus::keys::PreKey) -> CryptoKeystoreResult<()> {
        let prekey_buf = prekey.serialise()?;
        let entity = ProteusPrekey {
            id: prekey.key_id.value(),
            prekey: prekey_buf,
        };
        self.insert(entity).await?;
        Ok(())
    }
}

impl Connection {
    #[cfg(feature = "memory-cache")]
    #[inline(always)]
    fn proteus_memory_key<S: std::fmt::Display>(k: S) -> Vec<u8> {
        format!("proteus:{}", k).into_bytes()
    }
}

#[async_trait::async_trait(?Send)]
impl proteus::session::PreKeyStore for Connection {
    type Error = CryptoKeystoreError;

    async fn prekey(&mut self, id: proteus::keys::PreKeyId) -> Result<Option<proteus::keys::PreKey>, Self::Error> {
        #[cfg(feature = "memory-cache")]
        let memory_cache_key = Self::proteus_memory_key(id);

        #[cfg(feature = "memory-cache")]
        if self.is_cache_enabled() {
            let cache = self
                .memory_cache
                .lock()
                .await;

            if let Some(buf) = cache.get(&Self::proteus_memory_key(id)).map(Clone::clone) {
                return Ok(Some(proteus::keys::PreKey::deserialise(&buf)?));
            }
        }

        let mut db = self.conn.lock().await;

        let transaction = db.transaction()?;

        let maybe_row_id = transaction
            .query_row("SELECT rowid FROM proteus_prekeys WHERE id = ?", [id.value()], |r| {
                r.get::<_, u16>(0)
            })
            .optional()?;

        if let Some(row_id) = maybe_row_id {
            let mut blob = transaction.blob_open(
                rusqlite::DatabaseName::Main,
                "proteus_prekeys",
                "key",
                row_id as i64,
                true,
            )?;

            use std::io::Read as _;
            let mut buf = vec![];
            blob.read_to_end(&mut buf)?;
            let prekey = proteus::keys::PreKey::deserialise(&buf)?;

            #[cfg(feature = "memory-cache")]
            if self.is_cache_enabled() {
                self.memory_cache
                    .lock()
                    .await
                    .put(memory_cache_key, buf);
            }

            return Ok(Some(prekey));
        }

        Ok(None)
    }

    async fn remove(&mut self, id: proteus::keys::PreKeyId) -> Result<(), Self::Error> {
        #[cfg(feature = "memory-cache")]
        if self.is_cache_enabled() {
            let _ = self
                .memory_cache
                .lock()
                .await
                .pop(format!("proteus:{}", id).as_bytes());
        }

        let updated = self
            .conn
            .lock()
            .await
            .execute("DELETE FROM proteus_prekeys WHERE id = ?", [id.value()])?;

        if updated == 0 {
            return Err(MissingKeyErrorKind::ProteusPrekey.into());
        }

        Ok(())
    }
}
