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

use super::Entity;
use crate::CryptoKeystoreResult;
use zeroize::Zeroize;

#[derive(Debug, Clone, PartialEq, Eq, Zeroize)]
#[zeroize(drop)]
#[cfg_attr(target_family = "wasm", derive(serde::Serialize, serde::Deserialize))]
pub struct PersistedMlsGroup {
    pub id: Vec<u8>,
    pub state: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Zeroize)]
#[zeroize(drop)]
#[cfg_attr(target_family = "wasm", derive(serde::Serialize, serde::Deserialize))]
pub struct PersistedMlsPendingGroup {
    pub id: Vec<u8>,
    pub state: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Zeroize)]
#[zeroize(drop)]
#[cfg_attr(target_family = "wasm", derive(serde::Serialize, serde::Deserialize))]
pub struct MlsIdentity {
    pub id: String,
    pub signature: Vec<u8>,
    pub credential: Vec<u8>,
}

#[async_trait::async_trait(?Send)]
pub trait MlsIdentityExt: Entity {
    async fn find_by_signature(conn: &mut Self::ConnectionType, signature: &[u8])
        -> CryptoKeystoreResult<Option<Self>>;
    async fn delete_by_signature(conn: &mut Self::ConnectionType, signature: &[u8]) -> CryptoKeystoreResult<()>;
}

#[derive(Debug, Clone, PartialEq, Eq, Zeroize)]
#[zeroize(drop)]
#[cfg_attr(target_family = "wasm", derive(serde::Serialize, serde::Deserialize))]
pub struct MlsKeypackage {
    pub id: String,
    pub key: Vec<u8>,
}
