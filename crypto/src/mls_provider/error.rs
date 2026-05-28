#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    KeystoreError(#[from] core_crypto_keystore::CryptoKeystoreError),
    #[error("The provided entropy seed has an incorrect length: expected {expected}, found {actual}")]
    EntropySeedLengthError { actual: usize, expected: usize },
    #[error("CSPRNG lock is poisoned")]
    RngLockPoison,
    #[error("Unable to collect enough randomness.")]
    UnsufficientEntropy,
    #[error("An error occured while generating a X509 certificate")]
    CertificateGenerationError,
    #[error("This ciphersuite isn't supported as of now")]
    UnsupportedSignatureScheme,
    #[error(transparent)]
    SignatureError(#[from] signature::Error),
    #[error("{0}")]
    StringError(String),
}

#[allow(clippy::from_over_into)]
impl Into<String> for Error {
    fn into(self) -> String {
        self.to_string()
    }
}

/// Note: You *will* be losing context when cloning the error, because errors should never be `Clone`able,
/// but OpenMLS traits require it, so...let's do something that makes no sense.
impl Clone for Error {
    fn clone(&self) -> Self {
        Self::StringError(self.to_string())
    }
}

/// Note: You should never test errors for equality because stacktraces can be different, yet we're
/// constrained by OpenMLS to do this kind of things. So once again...
impl PartialEq for Error {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            // (MlsProviderError::KeystoreError(kse), MlsProviderError::KeystoreError(kse2)) => kse == kse2,
            (
                Error::EntropySeedLengthError { expected, actual },
                Error::EntropySeedLengthError {
                    expected: expected2,
                    actual: actual2,
                },
            ) => expected == expected2 && actual == actual2,
            (Error::StringError(s), Error::StringError(s2)) => s == s2,
            (Error::RngLockPoison, Error::RngLockPoison) => true,
            (Error::UnsufficientEntropy, Error::UnsufficientEntropy) => true,
            (Error::CertificateGenerationError, Error::CertificateGenerationError) => true,
            (Error::UnsupportedSignatureScheme, Error::UnsupportedSignatureScheme) => true,
            _ => false,
        }
    }
}

pub type MlsProviderResult<T> = Result<T, Error>;
