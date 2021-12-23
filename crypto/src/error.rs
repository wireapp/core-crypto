#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error(transparent)]
    KeyStoreError(#[from] core_crypto_keystore::CryptoKeystoreError),
    #[error(transparent)]
    MlsGroupError(#[from] openmls::group::MlsGroupError),
    #[error(transparent)]
    MlsErrorString(#[from] openmls::error::ErrorString),
    #[error(transparent)]
    // TODO: Fix inner proteus::session:Error type to not be self
    ProteusSessionError(#[from] proteus::session::Error<Box<CryptoError>>),
    #[error("The requested ({0}) configuration is not contained in this package")]
    ConfigurationMismatch(crate::Protocol),
    #[error(transparent)]
    Other(#[from] eyre::Report),
}

pub type CryptoResult<T> = Result<T, CryptoError>;
