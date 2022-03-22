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

#[derive(Debug, Clone)]
#[cfg_attr(target_family = "wasm", derive(serde::Serialize, serde::Deserialize))]
pub struct ProteusPrekey {
    pub id: u16,
    pub prekey: Vec<u8>,
}

impl TryFrom<proteus::keys::PreKey> for ProteusPrekey {
    type Error = crate::CryptoKeystoreError;
    fn try_from(prekey: proteus::keys::PreKey) -> crate::CryptoKeystoreResult<Self> {
        let id = prekey.key_id.value();
        let prekey = prekey.serialise()?;
        Ok(Self { id, prekey })
    }
}

impl TryInto<proteus::keys::PreKey> for ProteusPrekey {
    type Error = crate::CryptoKeystoreError;
    fn try_into(self) -> crate::CryptoKeystoreResult<proteus::keys::PreKey> {
        let prekey = proteus::keys::PreKey::deserialise(&self.prekey)?;
        Ok(prekey)
    }
}
