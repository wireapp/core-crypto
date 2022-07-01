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

/// Error to represent when a key is not present in the KeyStore
#[derive(Debug, Clone, PartialEq, thiserror::Error)]
pub enum MissingKeyErrorKind {
    #[error("MLS KeyPackageBundle")]
    MlsKeyPackageBundle,
    #[error("MLS CredentialBundle")]
    MlsIdentityBundle,
    #[error("MLS Persisted Group")]
    MlsGroup,
    #[error("MLS Persisted Pending Group")]
    MlsPendingGroup,
    #[cfg(feature = "proteus-keystore")]
    #[error("Proteus PreKey")]
    ProteusPrekey,
}

/// Error type to represent various errors that can happen in the KeyStore
#[derive(Debug, thiserror::Error)]
pub enum CryptoKeystoreError {
    #[error("The requested {0} is not present in the store")]
    MissingKeyInStore(#[from] MissingKeyErrorKind),
    #[error("The given key doesn't contain valid utf-8")]
    KeyReprError(#[from] std::str::Utf8Error),
    #[error(transparent)]
    TryFromSliceError(#[from] std::array::TryFromSliceError),
    #[error("One of the Keystore locks has been poisoned")]
    LockPoisonError,
    #[error("The keystore has run out of keypackage bundles!")]
    OutOfKeyPackageBundles,
    #[error("The provided buffer is too big to be persisted in the store")]
    BlobTooBig,
    #[cfg(feature = "mls-keystore")]
    #[error(transparent)]
    KeyStoreValueTransformError(Box<dyn std::error::Error + Send + Sync + 'static>),
    #[error(transparent)]
    IoError(#[from] std::io::Error),
    #[cfg(target_family = "wasm")]
    #[error(transparent)]
    ChannelError(#[from] std::sync::mpsc::TryRecvError),
    #[cfg(target_family = "wasm")]
    #[error("The task has been canceled")]
    WasmExecutorError,
    #[cfg(target_family = "wasm")]
    #[error("{0}")]
    RexieError(String),
    #[cfg(target_family = "wasm")]
    #[error("An IndexedDB timeout has occured")]
    RexieTimeoutError,
    #[cfg(target_family = "wasm")]
    #[error("aead::Error")]
    AesGcmError,
    #[cfg(target_family = "wasm")]
    #[error("{0}")]
    SerdeWasmBindgenError(String),
    #[cfg(not(target_family = "wasm"))]
    #[error(transparent)]
    DbError(#[from] rusqlite::Error),
    #[cfg(not(target_family = "wasm"))]
    #[error(transparent)]
    DbMigrationError(#[from] refinery::Error),
    #[cfg(test)]
    #[error(transparent)]
    MlsKeyPackageIdError(#[from] openmls::prelude::KeyPackageIdError),
    #[cfg(test)]
    #[error(transparent)]
    MlsExtensionError(#[from] openmls::prelude::ExtensionError),
    #[cfg(feature = "proteus-keystore")]
    #[error(transparent)]
    ParseIntError(#[from] std::num::ParseIntError),
    #[cfg(feature = "proteus-keystore")]
    #[error(transparent)]
    PrekeyDecodeError(#[from] proteus::internal::types::DecodeError),
    #[cfg(feature = "proteus-keystore")]
    #[error(transparent)]
    PrekeyEncodeError(#[from] proteus::internal::types::EncodeError),
    #[error("{0}")]
    MlsKeyStoreError(String),
    #[error(transparent)]
    HexDecodeError(#[from] hex::FromHexError),
    #[error(transparent)]
    FromUtf8Error(#[from] std::string::FromUtf8Error),
    #[cfg(feature = "ios-wal-compat")]
    #[error(transparent)]
    HexSaltDecodeError(hex::FromHexError),
    #[cfg(feature = "ios-wal-compat")]
    #[error(transparent)]
    SecurityFrameworkError(#[from] security_framework::base::Error),
    #[cfg(target_family = "wasm")]
    #[error("{0}")]
    JsError(String),
}

#[cfg(target_family = "wasm")]
impl From<wasm_bindgen::JsValue> for CryptoKeystoreError {
    fn from(jsv: wasm_bindgen::JsValue) -> Self {
        Self::JsError(jsv.as_string().unwrap())
    }
}

#[cfg(target_family = "wasm")]
#[allow(clippy::from_over_into)]
impl Into<wasm_bindgen::JsValue> for CryptoKeystoreError {
    fn into(self) -> wasm_bindgen::JsValue {
        wasm_bindgen::JsValue::from_str(&self.to_string())
    }
}

#[cfg(target_family = "wasm")]
impl From<serde_wasm_bindgen::Error> for CryptoKeystoreError {
    fn from(jsv: serde_wasm_bindgen::Error) -> Self {
        Self::SerdeWasmBindgenError(jsv.to_string())
    }
}

#[cfg(target_family = "wasm")]
impl From<rexie::Error> for CryptoKeystoreError {
    fn from(rexie_err: rexie::Error) -> Self {
        Self::RexieError(rexie_err.to_string())
    }
}

/// A specialized Result for the KeyStore functions
pub type CryptoKeystoreResult<T> = Result<T, CryptoKeystoreError>;
