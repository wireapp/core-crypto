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

use crate::{connection::Connection, entities::ProteusPrekey, CryptoKeystoreError, CryptoKeystoreResult};

#[async_trait::async_trait(?Send)]
pub trait CryptoKeystoreProteus {
    async fn proteus_store_prekey(&self, id: u16, prekey: &[u8]) -> CryptoKeystoreResult<()>;
}

#[async_trait::async_trait(?Send)]
impl CryptoKeystoreProteus for Connection {
    async fn proteus_store_prekey(&self, id: u16, prekey: &[u8]) -> CryptoKeystoreResult<()> {
        let entity = ProteusPrekey::from_raw(id, prekey.to_vec());
        self.save(entity).await?;
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
impl proteus_traits::PreKeyStore for Connection {
    type Error = CryptoKeystoreError;

    async fn prekey(
        &mut self,
        id: proteus_traits::RawPreKeyId,
    ) -> Result<Option<proteus_traits::RawPreKey>, Self::Error> {
        #[cfg(feature = "memory-cache")]
        if self.is_cache_enabled() {
            let mut cache = self.memory_cache.lock().await;

            if let Some(buf) = cache.get(&Self::proteus_memory_key(id)) {
                return Ok(Some(buf.clone()));
            }
        }

        Ok(self
            .find::<ProteusPrekey>(id.to_le_bytes())
            .await?
            .map(|db_prekey| db_prekey.prekey.clone()))
    }

    async fn remove(&mut self, id: proteus_traits::RawPreKeyId) -> Result<(), Self::Error> {
        #[cfg(feature = "memory-cache")]
        if self.is_cache_enabled() {
            let _ = self.memory_cache.lock().await.pop(format!("proteus:{}", id).as_bytes());
        }

        Connection::remove::<ProteusPrekey, _>(self, &id.to_le_bytes()).await?;

        Ok(())
    }
}
