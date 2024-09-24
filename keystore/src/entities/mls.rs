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
use crate::{connection::TransactionWrapper, CryptoKeystoreResult};
use openmls_traits::types::SignatureScheme;
use zeroize::Zeroize;

/// Entity representing a persisted `MlsGroup`
#[derive(Debug, Clone, PartialEq, Eq, Zeroize)]
#[zeroize(drop)]
#[cfg_attr(
    any(target_family = "wasm", feature = "serde"),
    derive(serde::Serialize, serde::Deserialize)
)]
pub struct PersistedMlsGroup {
    pub id: Vec<u8>,
    pub state: Vec<u8>,
    pub parent_id: Option<Vec<u8>>,
}

#[cfg_attr(target_family = "wasm", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_family = "wasm"), async_trait::async_trait)]
pub trait PersistedMlsGroupExt: Entity {
    fn parent_id(&self) -> Option<&[u8]>;

    async fn parent_group(
        &self,
        conn: &mut <Self as super::EntityBase>::ConnectionType,
    ) -> CryptoKeystoreResult<Option<Self>> {
        let Some(parent_id) = self.parent_id() else {
            return Ok(None);
        };

        <Self as super::EntityBase>::find_one(conn, &parent_id.into()).await
    }

    async fn child_groups(
        &self,
        conn: &mut <Self as super::EntityBase>::ConnectionType,
    ) -> CryptoKeystoreResult<Vec<Self>> {
        let entities = <Self as super::EntityBase>::find_all(conn, super::EntityFindParams::default()).await?;

        let id = self.id_raw();

        Ok(entities
            .into_iter()
            .filter(|entity| entity.parent_id().map(|parent_id| parent_id == id).unwrap_or_default())
            .collect())
    }
}

/// Entity representing a temporarily persisted `MlsGroup`
#[derive(Debug, Clone, PartialEq, Eq, Zeroize)]
#[zeroize(drop)]
#[cfg_attr(
    any(target_family = "wasm", feature = "serde"),
    derive(serde::Serialize, serde::Deserialize)
)]
pub struct PersistedMlsPendingGroup {
    pub id: Vec<u8>,
    pub state: Vec<u8>,
    pub parent_id: Option<Vec<u8>>,
    pub custom_configuration: Vec<u8>,
}

/// Entity representing a buffered message
#[derive(Debug, Clone, PartialEq, Eq, Zeroize)]
#[zeroize(drop)]
#[cfg_attr(
    any(target_family = "wasm", feature = "serde"),
    derive(serde::Serialize, serde::Deserialize)
)]
pub struct MlsPendingMessage {
    pub id: Vec<u8>,
    pub message: Vec<u8>,
}

/// Entity representing a persisted `Credential`
#[derive(Debug, Clone, PartialEq, Eq, Zeroize)]
#[zeroize(drop)]
#[cfg_attr(
    any(target_family = "wasm", feature = "serde"),
    derive(serde::Serialize, serde::Deserialize)
)]
pub struct MlsCredential {
    pub id: Vec<u8>,
    pub credential: Vec<u8>,
    pub created_at: u64,
}

/// Entity representing a persisted `SignatureKeyPair`
#[derive(Debug, Clone, PartialEq, Eq, Zeroize)]
#[zeroize(drop)]
#[cfg_attr(
    any(target_family = "wasm", feature = "serde"),
    derive(serde::Serialize, serde::Deserialize)
)]
pub struct MlsSignatureKeyPair {
    pub signature_scheme: u16,
    pub pk: Vec<u8>,
    pub keypair: Vec<u8>,
    pub credential_id: Vec<u8>,
}

impl MlsSignatureKeyPair {
    pub fn new(signature_scheme: SignatureScheme, pk: Vec<u8>, keypair: Vec<u8>, credential_id: Vec<u8>) -> Self {
        Self {
            signature_scheme: signature_scheme as u16,
            pk,
            keypair,
            credential_id,
        }
    }
}

/// Entity representing a persisted `HpkePrivateKey` (related to LeafNode Private keys that the client is aware of)
#[derive(Debug, Clone, PartialEq, Eq, Zeroize)]
#[zeroize(drop)]
#[cfg_attr(
    any(target_family = "wasm", feature = "serde"),
    derive(serde::Serialize, serde::Deserialize)
)]
pub struct MlsHpkePrivateKey {
    pub sk: Vec<u8>,
    pub pk: Vec<u8>,
}

/// Entity representing a persisted `HpkePrivateKey` (related to LeafNode Private keys that the client is aware of)
#[derive(Debug, Clone, PartialEq, Eq, Zeroize)]
#[zeroize(drop)]
#[cfg_attr(
    any(target_family = "wasm", feature = "serde"),
    derive(serde::Serialize, serde::Deserialize)
)]
pub struct MlsEncryptionKeyPair {
    pub sk: Vec<u8>,
    pub pk: Vec<u8>,
}

/// Entity representing a list of [MlsEncryptionKeyPair]
#[derive(Debug, Clone, PartialEq, Eq, Zeroize)]
#[zeroize(drop)]
#[cfg_attr(target_family = "wasm", derive(serde::Serialize, serde::Deserialize))]
pub struct MlsEpochEncryptionKeyPair {
    pub id: Vec<u8>,
    pub keypairs: Vec<u8>,
}

/// Entity representing a persisted `SignatureKeyPair`
#[derive(Debug, Clone, PartialEq, Eq, Zeroize)]
#[zeroize(drop)]
#[cfg_attr(
    any(target_family = "wasm", feature = "serde"),
    derive(serde::Serialize, serde::Deserialize)
)]
pub struct MlsPskBundle {
    pub psk_id: Vec<u8>,
    pub psk: Vec<u8>,
}

/// Entity representing a persisted `KeyPackage`
#[derive(Debug, Clone, PartialEq, Eq, Zeroize)]
#[zeroize(drop)]
#[cfg_attr(
    any(target_family = "wasm", feature = "serde"),
    derive(serde::Serialize, serde::Deserialize)
)]
pub struct MlsKeyPackage {
    pub keypackage_ref: Vec<u8>,
    pub keypackage: Vec<u8>,
}

/// Entity representing an enrollment instance used to fetch a x509 certificate and persisted when
/// context switches and the memory it lives in is about to be erased
#[derive(Debug, Clone, PartialEq, Eq, Zeroize)]
#[zeroize(drop)]
#[cfg_attr(
    any(target_family = "wasm", feature = "serde"),
    derive(serde::Serialize, serde::Deserialize)
)]
pub struct E2eiEnrollment {
    pub id: Vec<u8>,
    pub content: Vec<u8>,
}

#[cfg_attr(target_family = "wasm", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_family = "wasm"), async_trait::async_trait)]
pub trait UniqueEntity: Entity {
    const ID: [u8; 1] = [0];
    async fn find_unique(conn: &mut Self::ConnectionType) -> CryptoKeystoreResult<Self>;
    async fn replace(&self, conn: &mut Self::ConnectionType) -> CryptoKeystoreResult<()>;
}

/// OIDC refresh token used in E2EI
#[derive(Debug, Clone, PartialEq, Eq, Zeroize)]
#[zeroize(drop)]
#[cfg_attr(
    any(target_family = "wasm", feature = "serde"),
    derive(serde::Serialize, serde::Deserialize)
)]
pub struct E2eiRefreshToken {
    pub content: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Zeroize)]
#[zeroize(drop)]
#[cfg_attr(
    any(target_family = "wasm", feature = "serde"),
    derive(serde::Serialize, serde::Deserialize)
)]
pub struct E2eiAcmeCA {
    pub content: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Zeroize)]
#[zeroize(drop)]
#[cfg_attr(
    any(target_family = "wasm", feature = "serde"),
    derive(serde::Serialize, serde::Deserialize)
)]
pub struct E2eiIntermediateCert {
    // key to identify the CA cert; Using a combination of SKI & AKI extensions concatenated like so is suitable: `SKI[+AKI]`
    pub ski_aki_pair: String,
    pub content: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Zeroize)]
#[zeroize(drop)]
#[cfg_attr(
    any(target_family = "wasm", feature = "serde"),
    derive(serde::Serialize, serde::Deserialize)
)]
pub struct E2eiCrl {
    pub distribution_point: String,
    pub content: Vec<u8>,
}
