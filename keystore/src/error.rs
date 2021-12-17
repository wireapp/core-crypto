
#[derive(Debug, thiserror::Error)]
pub enum CryptoKeystoreError {
    #[error(transparent)]
    DbError(#[from] rusqlite::Error),
    #[error(transparent)]
    DbMigrationError(#[from] refinery::Error),
    #[error(transparent)]
    KeyPackageError(#[from] openmls::prelude::KeyPackageError),
    #[error("{0}")]
    MlsKeyStoreError(String),
    #[error(transparent)]
    UuidError(#[from] uuid::Error),
    #[error(transparent)]
    Other(#[from] eyre::Report)
}

pub type CryptoKeystoreResult<T> = Result<T, CryptoKeystoreError>;
