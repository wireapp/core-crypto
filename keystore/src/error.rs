#[derive(Debug, thiserror::Error)]
pub enum MissingKeyErrorKind {
    #[error("MLS Key Bundle")]
    MlsKeyBundle,
    #[error("Proteus PreKey")]
    ProteusPrekey,
}

#[derive(Debug, thiserror::Error)]
pub enum CryptoKeystoreError {
    #[error("The requested {0} is not present in the store")]
    MissingKeyInStore(#[from] MissingKeyErrorKind),
    #[error("One of the locks has been poisoned")]
    LockPoisonError,
    #[error(transparent)]
    IoError(#[from] std::io::Error),
    #[error(transparent)]
    DbError(#[from] rusqlite::Error),
    #[error(transparent)]
    DbMigrationError(#[from] refinery::Error),
    #[error(transparent)]
    KeyPackageError(#[from] openmls::prelude::KeyPackageError),
    #[error(transparent)]
    PrekeyDecodeError(#[from] proteus::internal::types::DecodeError),
    #[error(transparent)]
    PrekeyEncodeError(#[from] proteus::internal::types::EncodeError),
    #[error("{0}")]
    MlsKeyStoreError(String),
    #[error(transparent)]
    UuidError(#[from] uuid::Error),
    #[error(transparent)]
    Other(#[from] eyre::Report),
}

pub type CryptoKeystoreResult<T> = Result<T, CryptoKeystoreError>;
