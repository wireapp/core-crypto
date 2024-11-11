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

pub(crate) mod general;
pub(crate) mod mls;

pub use self::general::*;
pub use self::mls::*;

cfg_if::cfg_if! {
    if #[cfg(feature = "proteus-keystore")] {
        pub(crate) mod proteus;
        pub use self::proteus::*;
    }
}

mod platform {
    cfg_if::cfg_if! {
        if #[cfg(target_family = "wasm")] {
            mod wasm;
            pub use self::wasm::*;
        } else {
            mod generic;
            pub use self::generic::*;
        }
    }
}

pub use self::platform::*;

use crate::connection::DatabaseConnection;
#[cfg(not(target_family = "wasm"))]
use crate::sha256;
use crate::{CryptoKeystoreError, CryptoKeystoreResult, MissingKeyErrorKind};

#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[cfg_attr(
    any(target_family = "wasm", feature = "serde"),
    derive(serde::Serialize, serde::Deserialize)
)]
#[repr(transparent)]
pub struct StringEntityId<'a>(&'a [u8]);

impl<'a> StringEntityId<'a> {
    pub fn new(bytes: &'a [u8]) -> Self {
        Self(bytes)
    }

    pub fn as_hex_string(&self) -> String {
        hex::encode(self.0)
    }

    #[cfg(not(target_family = "wasm"))]
    pub(crate) fn sha256(&self) -> String {
        sha256(self.0)
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.into()
    }

    pub fn as_slice(&self) -> &[u8] {
        self.0
    }

    pub fn try_as_str(&self) -> Result<&str, ::core::str::Utf8Error> {
        std::str::from_utf8(self.0)
    }
}

impl TryInto<String> for &StringEntityId<'_> {
    type Error = CryptoKeystoreError;

    fn try_into(self) -> CryptoKeystoreResult<String> {
        Ok(String::from_utf8(self.0.into())?)
    }
}

impl std::fmt::Display for StringEntityId<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_hex_string())
    }
}

impl<'a> From<&'a [u8]> for StringEntityId<'a> {
    fn from(bytes: &'a [u8]) -> Self {
        Self::new(bytes)
    }
}

#[derive(Debug, Clone, Default)]
pub struct EntityFindParams {
    pub limit: Option<u32>,
    pub offset: Option<u32>,
    pub reverse: bool,
}

#[cfg(not(target_family = "wasm"))]
impl EntityFindParams {
    pub fn to_sql(&self) -> String {
        use std::fmt::Write as _;
        let mut query: String = "".into();
        if let Some(offset) = self.offset {
            let _ = write!(query, " OFFSET {offset}");
        }
        let _ = write!(query, " ORDER BY rowid");
        if self.reverse {
            let _ = write!(query, " DESC");
        }
        if let Some(limit) = self.limit {
            let _ = write!(query, " LIMIT {limit}");
        }

        query
    }
}

#[cfg_attr(target_family = "wasm", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_family = "wasm"), async_trait::async_trait)]
pub trait EntityBase: Send + Sized + Clone + PartialEq + Eq + std::fmt::Debug {
    type ConnectionType: DatabaseConnection;
    type AutoGeneratedFields: Default;
    /// Beware: if you change the value of this constant on any WASM entity, you'll need to do a data migration
    ///     not only because it is used as reference to the object store names but also for the value of the aad.
    const COLLECTION_NAME: &'static str;

    fn to_missing_key_err_kind() -> MissingKeyErrorKind;

    fn downcast<T: EntityBase>(&self) -> Option<&T> {
        if T::COLLECTION_NAME == Self::COLLECTION_NAME {
            // SAFETY: The above check ensures that this transmutation is safe.
            Some(unsafe { std::mem::transmute::<&Self, &T>(self) })
        } else {
            None
        }
    }

    fn to_transaction_entity(self) -> crate::transaction::dynamic_dispatch::Entity;

    async fn find_all(conn: &mut Self::ConnectionType, params: EntityFindParams) -> CryptoKeystoreResult<Vec<Self>>;
    async fn find_one(conn: &mut Self::ConnectionType, id: &StringEntityId) -> CryptoKeystoreResult<Option<Self>>;
    async fn find_many(conn: &mut Self::ConnectionType, ids: &[StringEntityId]) -> CryptoKeystoreResult<Vec<Self>> {
        // Default, inefficient & naive method
        let mut ret = Vec::with_capacity(ids.len());
        for id in ids {
            if let Some(entity) = Self::find_one(conn, id).await? {
                ret.push(entity);
            }
        }

        Ok(ret)
    }
    async fn count(conn: &mut Self::ConnectionType) -> CryptoKeystoreResult<usize>;
}

cfg_if::cfg_if! {
    if #[cfg(target_family = "wasm")] {
        const AES_GCM_256_NONCE_SIZE: usize = 12;

        #[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
        struct Aad {
            type_name: Vec<u8>,
            id: Vec<u8>,
        }

        #[async_trait::async_trait(?Send)]
        pub trait EntityTransactionExt: Entity<ConnectionType = crate::connection::KeystoreDatabaseConnection> {
            async fn save<'a>(&'a self, tx: &crate::connection::storage::WasmStorageTransaction<'a>) -> CryptoKeystoreResult<()> {
                tx.save(self.clone()).await
            }
            async fn pre_save<'a>(&'a mut self) -> CryptoKeystoreResult<Self::AutoGeneratedFields> {
                Ok(Default::default())
            }
            async fn delete_fail_on_missing_id<'a>(tx: &crate::connection::storage::WasmStorageTransaction<'a>, id: StringEntityId<'a>) -> CryptoKeystoreResult<()> {
                tx.delete(Self::COLLECTION_NAME, id.as_slice()).await
            }

            async fn delete<'a>(tx: &crate::connection::storage::WasmStorageTransaction<'a>, id: StringEntityId<'a>) -> CryptoKeystoreResult<()> {
                match Self::delete_fail_on_missing_id(tx, id).await{
                    Ok(_) => Ok(()),
                    Err(CryptoKeystoreError::IdbError(idb::Error::DeleteFailed(_))) => Ok(()),
                    Err(e) => Err(e),
                }
            }
        }

        pub trait Entity: EntityBase + serde::Serialize + serde::de::DeserializeOwned {
            fn id(&self) -> CryptoKeystoreResult<wasm_bindgen::JsValue> {
                Ok(js_sys::Uint8Array::from(self.id_raw()).into())
            }

            fn id_raw(&self) -> &[u8];

            /// The query results that are obtained during a transaction
            /// from the transaction cache and the database are merged by this key.
            fn merge_key(&self) -> Vec<u8> {
                self.id_raw().into()
            }

            fn aad(&self) -> CryptoKeystoreResult<Vec<u8>> {
                let aad = Aad {
                    type_name: Self::COLLECTION_NAME.as_bytes().to_vec(),
                    id: self.id_raw().into(),
                };
                serde_json::to_vec(&aad).map_err(Into::into)
            }
            // About WASM Encryption:
            // The store key (i.e. passphrase) is hashed using SHA256 to obtain 32 bytes
            // The AES256-GCM cipher is then initialized and is used to encrypt individual values
            // Entities shall decide which fields need to be encrypted
            // Internal layout:
            // - Cleartext: [u8] bytes
            // - Ciphertext: [12 bytes of nonce..., ...encrypted data]
            fn encrypt(&mut self, cipher: &aes_gcm::Aes256Gcm) -> CryptoKeystoreResult<()>;
            fn encrypt_with_nonce_and_aad(cipher: &aes_gcm::Aes256Gcm, data: &[u8], nonce: &[u8], aad: &[u8]) -> CryptoKeystoreResult<Vec<u8>> {
                use aes_gcm::aead::Aead as _;
                let nonce = aes_gcm::Nonce::from_slice(nonce);
                let msg = data;
                let payload = aes_gcm::aead::Payload {
                    msg,
                    aad,
                };

                let mut encrypted = cipher.encrypt(nonce, payload).map_err(|_| CryptoKeystoreError::AesGcmError)?;
                let mut message = Vec::with_capacity(nonce.len() + encrypted.len());
                message.extend_from_slice(nonce);
                message.append(&mut encrypted);
                Ok(message)
            }

            fn encrypt_data(&self, cipher: &aes_gcm::Aes256Gcm, data: &[u8]) -> CryptoKeystoreResult<Vec<u8>> {
                let nonce_bytes: [u8; AES_GCM_256_NONCE_SIZE] = rand::random();
                Self::encrypt_with_nonce_and_aad(cipher, data, &nonce_bytes, &self.aad()?)
            }

            fn decrypt(&mut self, cipher: &aes_gcm::Aes256Gcm) -> CryptoKeystoreResult<()>;
            fn decrypt_data(&self, cipher: &aes_gcm::Aes256Gcm, data: &[u8]) -> CryptoKeystoreResult<Vec<u8>> {
                use aes_gcm::aead::Aead as _;

                if data.is_empty() {
                    return Err(CryptoKeystoreError::MissingKeyInStore(Self::to_missing_key_err_kind()));
                }
                if data.len() < AES_GCM_256_NONCE_SIZE {
                    return Err(CryptoKeystoreError::AesGcmError);
                }

                let nonce_bytes = &data[..AES_GCM_256_NONCE_SIZE];
                let nonce = aes_gcm::Nonce::from_slice(nonce_bytes);
                let msg = &data[AES_GCM_256_NONCE_SIZE..];
                let aad = &self.aad()?;
                let payload = aes_gcm::aead::Payload {
                    msg,
                    aad,
                };
                let cleartext = cipher.decrypt(nonce, payload).map_err(|_| CryptoKeystoreError::AesGcmError)?;
                Ok(cleartext)
            }
        }
    } else {
        #[async_trait::async_trait]
        pub trait EntityTransactionExt: Entity {
            async fn save(&self, tx: &crate::connection::TransactionWrapper<'_>) -> CryptoKeystoreResult<()>;
            async fn pre_save<'a>(&'a mut self) -> CryptoKeystoreResult<Self::AutoGeneratedFields> {
                Ok(Default::default())
            }
            async fn delete_fail_on_missing_id(
                tx: &crate::connection::TransactionWrapper<'_>,
                id: StringEntityId<'_>,
            ) -> CryptoKeystoreResult<()>;

            async fn delete(
                tx: &crate::connection::TransactionWrapper<'_>,
                id: StringEntityId<'_>,
            ) -> CryptoKeystoreResult<()> {
                match Self::delete_fail_on_missing_id(tx, id).await{
                    Ok(_) => Ok(()),
                    Err(CryptoKeystoreError::MissingKeyInStore(_)) => Ok(()),
                    Err(e) => Err(e),
                }
            }
        }

        pub trait Entity: EntityBase {
            fn id_raw(&self) -> &[u8];

            /// The query results that are obtained during a transaction
            /// from the transaction cache and the database are merged by this key.
            fn merge_key(&self) -> Vec<u8> {
                self.id_raw().into()
            }
        }

        pub trait EntityIdStringExt: Entity {
            fn id_hex(&self) -> String {
                hex::encode(self.id_raw())
            }

            fn id_sha256(&self) -> String {
                sha256(self.id_raw())
            }

            fn id_from_hex(id_hex: &str) -> CryptoKeystoreResult<Vec<u8>> {
                hex::decode(id_hex).map_err(Into::into)
            }
        }

        impl<T: Entity> EntityIdStringExt for T {}
    }
}
