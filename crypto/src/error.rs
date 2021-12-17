
#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error(transparent)]
    Other(#[from] eyre::Report)
}

pub type CryptoResult<T> = Result<T, CryptoError>;
