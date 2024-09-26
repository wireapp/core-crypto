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
#[cfg(target_family = "wasm")]
use crate::connection::storage::WasmEncryptedStorage;
use crate::{connection::TransactionWrapper, CryptoKeystoreError, CryptoKeystoreResult};
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

#[cfg_attr(target_family = "wasm", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_family = "wasm"), async_trait::async_trait)]
pub trait MlsCredentialExt: Entity {
    async fn delete_by_credential(tx: &TransactionWrapper<'_>, credential: Vec<u8>) -> CryptoKeystoreResult<()>;
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
pub trait UniqueEntity: Entity<ConnectionType=crate::connection::KeystoreDatabaseConnection>
where
    Self: 'static,
{
    cfg_if::cfg_if! {
        if #[cfg(target_family = "wasm")] {
            const ID: [u8; 1] = [0];

            async fn find_unique(conn: &mut Self::ConnectionType) -> CryptoKeystoreResult<Self> {
                Ok(conn
                    .storage()
                    .get(Self::COLLECTION_NAME, &Self::ID)
                    .await?
                    .ok_or(CryptoKeystoreError::NotFound(Self::COLLECTION_NAME, "".to_string()))?)
            }

            async fn replace(&self, conn: &mut Self::ConnectionType) -> CryptoKeystoreResult<()> {
                let storage = conn.storage_mut();
                storage.save(Self::COLLECTION_NAME, &mut [self.clone()]).await?;
                Ok(())
            }
        } else {
            const ID: usize = 0;

            fn new(content: Vec<u8>) -> Self;

            async fn find_unique(conn: &mut Self::ConnectionType) -> CryptoKeystoreResult<Self> {
                let transaction = conn.transaction()?;
                use rusqlite::OptionalExtension as _;

                let maybe_content = transaction
                    .query_row(&format!("SELECT content FROM {} WHERE id = ?", Self::COLLECTION_NAME), [Self::ID], |r| {
                        r.get::<_, Vec<u8>>(0)
                    })
                    .optional()?;

                if let Some(content) = maybe_content {
                    Ok(Self::new(content))
                } else {
                    Err(CryptoKeystoreError::NotFound(Self::COLLECTION_NAME, "".to_string()))
                }
            }

            fn content(&self) -> &[u8];

            async fn replace(&self, conn: &mut Self::ConnectionType) -> CryptoKeystoreResult<()> {
                use crate::connection::DatabaseConnection;
                Self::ConnectionType::check_buffer_size(self.content().len())?;
                let zb_content = rusqlite::blob::ZeroBlob(self.content().len() as i32);

                let transaction = conn.transaction()?;
                use rusqlite::ToSql;
                let params: [rusqlite::types::ToSqlOutput; 2] = [Self::ID.to_sql()?, zb_content.to_sql()?];

                transaction.execute(
                    &format!("INSERT OR REPLACE INTO {} (id, content) VALUES (?, ?)", Self::COLLECTION_NAME),
                    params,
                )?;
                let row_id = transaction.last_insert_rowid();

                let mut blob = transaction.blob_open(
                    rusqlite::DatabaseName::Main,
                    Self::COLLECTION_NAME,
                    "content",
                    row_id,
                    false,
                )?;
                use std::io::Write;
                blob.write_all(self.content())?;
                blob.close()?;

                Ok(())
            }
        }
    }
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
