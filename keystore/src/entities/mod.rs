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

// TODO: Test all methods of all entities (rstest fixtures?)
cfg_if::cfg_if! {
    if #[cfg(feature = "mls-keystore")] {
        mod mls;
        pub use self::mls::*;
    }
}

cfg_if::cfg_if! {
    if #[cfg(feature = "proteus-keystore")] {
        mod proteus;
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
use crate::{CryptoKeystoreError, CryptoKeystoreResult, MissingKeyErrorKind};

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(target_family = "wasm", derive(serde::Serialize, serde::Deserialize))]
#[repr(transparent)]
pub struct StringEntityId<'a>(&'a [u8]);

impl<'a> StringEntityId<'a> {
    pub fn new(bytes: &'a [u8]) -> Self {
        Self(bytes)
    }

    pub fn as_hex_string(&self) -> String {
        hex::encode(self.0)
    }

    pub fn as_bytes(&self) -> Vec<u8> {
        self.0.into()
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

#[async_trait::async_trait(?Send)]
pub trait EntityBase: Send + Sized + Clone + std::fmt::Debug {
    type ConnectionType: DatabaseConnection;

    fn to_missing_key_err_kind() -> MissingKeyErrorKind;

    async fn save(&self, conn: &mut Self::ConnectionType) -> CryptoKeystoreResult<()>;
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
    async fn delete(conn: &mut Self::ConnectionType, id: &StringEntityId) -> CryptoKeystoreResult<()>;
}

cfg_if::cfg_if! {
    if #[cfg(target_family = "wasm")] {
        const AES_CBC_256_NONCE_SIZE: usize = 12;

        pub trait Entity: EntityBase + serde::Serialize + serde::de::DeserializeOwned {
            fn id(&self) -> CryptoKeystoreResult<wasm_bindgen::JsValue> {
                Ok(js_sys::Uint8Array::from(self.id_raw()).into())
            }

            fn id_raw(&self) -> &[u8] {
                self.aad()
            }

            fn aad(&self) -> &[u8];
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

            fn encrypt_data(cipher: &aes_gcm::Aes256Gcm, data: &[u8], aad: &[u8]) -> CryptoKeystoreResult<Vec<u8>> {
                let nonce_bytes: [u8; AES_CBC_256_NONCE_SIZE] = rand::random();
                Self::encrypt_with_nonce_and_aad(cipher, data, &nonce_bytes, aad)
            }

            fn reencrypt_data(cipher: &aes_gcm::Aes256Gcm, encrypted: &[u8], clear: &[u8], aad: &[u8]) -> CryptoKeystoreResult<Vec<u8>> {
                let nonce_bytes = &encrypted[..AES_CBC_256_NONCE_SIZE];
                Self::encrypt_with_nonce_and_aad(cipher, clear, nonce_bytes, aad)
            }

            fn decrypt(&mut self, cipher: &aes_gcm::Aes256Gcm) -> CryptoKeystoreResult<()>;
            fn decrypt_data(cipher: &aes_gcm::Aes256Gcm, data: &[u8], aad: &[u8]) -> CryptoKeystoreResult<Vec<u8>> {
                use aes_gcm::aead::Aead as _;

                let nonce_bytes = &data[..AES_CBC_256_NONCE_SIZE];
                let nonce = aes_gcm::Nonce::from_slice(nonce_bytes);
                let msg = &data[AES_CBC_256_NONCE_SIZE..];
                let payload = aes_gcm::aead::Payload {
                    msg,
                    aad,
                };
                let cleartext = cipher.decrypt(nonce, payload).map_err(|_| CryptoKeystoreError::AesGcmError)?;
                Ok(cleartext)
            }
        }
    } else {
        pub trait Entity: EntityBase {}
    }
}
