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

use crate::keystore_v_1_0_0::{connection::Connection, entities::ProteusPrekey, CryptoKeystoreError};

#[cfg_attr(target_family = "wasm", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_family = "wasm"), async_trait::async_trait)]
impl proteus_traits::PreKeyStore for Connection {
    type Error = CryptoKeystoreError;

    async fn prekey(
        &mut self,
        id: proteus_traits::RawPreKeyId,
    ) -> Result<Option<proteus_traits::RawPreKey>, Self::Error> {
        Ok(self
            .find::<ProteusPrekey>(id.to_le_bytes())
            .await?
            .map(|db_prekey| db_prekey.prekey.clone()))
    }

    async fn remove(&mut self, id: proteus_traits::RawPreKeyId) -> Result<(), Self::Error> {
        Connection::remove::<ProteusPrekey, _>(self, id.to_le_bytes()).await?;

        Ok(())
    }
}
