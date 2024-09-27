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

use crate::CryptoError;

/// A Client identifier
///
/// A unique identifier for clients. A client is an identifier for each App a user is using, such as desktop,
/// mobile, etc. Users can have multiple clients.
/// More information [here](https://messaginglayersecurity.rocks/mls-architecture/draft-ietf-mls-architecture.html#name-group-members-and-clients)
#[derive(Debug, Clone, PartialEq, Eq, Hash, derive_more::Deref)]
pub struct ClientId(pub(crate) Vec<u8>);

impl From<&[u8]> for ClientId {
    fn from(value: &[u8]) -> Self {
        Self(value.into())
    }
}

impl From<Vec<u8>> for ClientId {
    fn from(value: Vec<u8>) -> Self {
        Self(value)
    }
}

impl From<Box<[u8]>> for ClientId {
    fn from(value: Box<[u8]>) -> Self {
        Self(value.into())
    }
}

impl From<ClientId> for Box<[u8]> {
    fn from(value: ClientId) -> Self {
        value.0.into_boxed_slice()
    }
}

#[cfg(test)]
impl From<&str> for ClientId {
    fn from(value: &str) -> Self {
        Self(value.as_bytes().into())
    }
}

#[allow(clippy::from_over_into)]
impl Into<Vec<u8>> for ClientId {
    fn into(self) -> Vec<u8> {
        self.0
    }
}

impl std::fmt::Display for ClientId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self.0.as_slice()))
    }
}

impl std::str::FromStr for ClientId {
    type Err = CryptoError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self(
            hex::decode(s).map_or_else(|_| s.as_bytes().to_vec(), std::convert::identity),
        ))
    }
}
