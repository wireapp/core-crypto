#[derive(Debug, thiserror::Error)]
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
    #[error(transparent)]
    IoError(#[from] std::io::Error),
    #[error(transparent)]
    DbError(#[from] rusqlite::Error),
    #[error(transparent)]
    DbMigrationError(#[from] refinery::Error),
    #[cfg(test)]
    #[error(transparent)]
    KeyPackageError(#[from] openmls::prelude::KeyPackageError),
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

// impl Into<String> for CryptoKeystoreError {
//     fn into(self) -> String {
//         format!("{}", self)
//     }
// }

// impl PartialEq for CryptoKeystoreError {
//     fn eq(&self, other: &Self) -> bool {
//         match (self, other) {
//             (CryptoKeystoreError::MissingKeyInStore(_), CryptoKeystoreError::MissingKeyInStore(_)) => true,
//             (CryptoKeystoreError::KeyReprError(_), CryptoKeystoreError::KeyReprError(_)) => true,
//             (CryptoKeystoreError::LockPoisonError, CryptoKeystoreError::LockPoisonError) => true,
//             (CryptoKeystoreError::IoError(_), CryptoKeystoreError::IoError(_)) => true,
//             (CryptoKeystoreError::DbError(_), CryptoKeystoreError::DbError(_)) => true,
//             (CryptoKeystoreError::DbMigrationError(_), CryptoKeystoreError::DbMigrationError(_)) => true,
//             #[cfg(test)]
//             (CryptoKeystoreError::KeyPackageError(_), CryptoKeystoreError::KeyPackageError(_)) => true,
//             (CryptoKeystoreError::MlsKeyStoreError(_), CryptoKeystoreError::MlsKeyStoreError(_)) => true,
//             #[cfg(feature = "proteus_keystore")]
//             (CryptoKeystoreError::PrekeyDecodeError(_), CryptoKeystoreError::PrekeyDecodeError(_)) => true,
//             #[cfg(feature = "proteus_keystore")]
//             (CryptoKeystoreError::PrekeyEncodeError(_), CryptoKeystoreError::PrekeyEncodeError(_)) => true,
//             #[cfg(feature = "ios-wal-compat")]
//             (CryptoKeystoreError::HexSaltDecodeError(_), CryptoKeystoreError::HexSaltDecodeError(_)) => true,
//             (CryptoKeystoreError::UuidError(_), CryptoKeystoreError::UuidError(_)) => true,
//             (CryptoKeystoreError::Other(_), CryptoKeystoreError::Other(_)) => false,
//             _ => false,
//         }
//     }
// }

pub type CryptoKeystoreResult<T> = Result<T, CryptoKeystoreError>;
