#[derive(Debug, thiserror::Error, Clone, PartialEq)]
pub enum Error {
    #[error("The provided entropy seed has an incorrect length: expected {expected}, found {actual}")]
    EntropySeedLength { actual: usize, expected: usize },
    #[error("CSPRNG lock is poisoned")]
    RngLockPoison,
    #[error("Unable to collect enough randomness.")]
    UnsufficientEntropy,
    #[error("This ciphersuite isn't supported as of now")]
    UnsupportedSignatureScheme,
    #[error("{0}")]
    Generic(String),
}

#[allow(clippy::from_over_into)]
impl Into<String> for Error {
    fn into(self) -> String {
        self.to_string()
    }
}

pub type MlsProviderResult<T> = Result<T, Error>;
