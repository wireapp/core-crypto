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

#[derive(Debug, Clone, PartialEq, thiserror::Error)]
pub enum MissingKeyErrorKind {
    #[error("MLS Key Bundle")]
    MlsKeyBundle,
    #[cfg(feature = "proteus-keystore")]
    #[error("Proteus PreKey")]
    ProteusPrekey,
}

#[derive(Debug, thiserror::Error)]
pub enum CryptoKeystoreError {
    #[error("The requested {0} is not present in the store")]
    MissingKeyInStore(#[from] MissingKeyErrorKind),
    #[error("The given key doesn't contain valid utf-8")]
    KeyReprError(std::str::Utf8Error),
    #[error("One of the locks has been poisoned")]
    LockPoisonError,
    #[error("The keystore has run out of keypackage bundles!")]
    OutOfKeyPackageBundles,
    #[error("{0}")]
    KeyStoreValueTransformError(String),
    #[error(transparent)]
    IoError(#[from] std::io::Error),
    #[error(transparent)]
    DbError(#[from] rusqlite::Error),
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
    PrekeyDecodeError(#[from] proteus::internal::types::DecodeError),
    #[cfg(feature = "proteus-keystore")]
    #[error(transparent)]
    PrekeyEncodeError(#[from] proteus::internal::types::EncodeError),
    #[error("{0}")]
    MlsKeyStoreError(String),
    #[error(transparent)]
    UuidError(#[from] uuid::Error),
    #[cfg(feature = "ios-wal-compat")]
    #[error(transparent)]
    HexSaltDecodeError(#[from] hex::FromHexError),
    #[cfg(feature = "ios-wal-compat")]
    #[error(transparent)]
    SecurityFrameworkError(#[from] security_framework::base::Error),
    #[error(transparent)]
    Other(#[from] eyre::Report),
}

pub type CryptoKeystoreResult<T> = Result<T, CryptoKeystoreError>;
