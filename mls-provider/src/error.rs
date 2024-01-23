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

#[derive(Debug, thiserror::Error)]
pub enum MlsProviderError {
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
impl Into<String> for MlsProviderError {
    fn into(self) -> String {
        self.to_string()
    }
}

/// Note: You *will* be losing context when cloning the error, because errors should never be `Clone`able,
/// but OpenMLS traits require it, so...let's do something that makes no sense.
impl Clone for MlsProviderError {
    fn clone(&self) -> Self {
        Self::StringError(self.to_string())
    }
}

/// Note: You should never test errors for equality because stacktraces can be different, yet we're
/// constrained by OpenMLS to do this kind of things. So once again...
impl PartialEq for MlsProviderError {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            // (MlsProviderError::KeystoreError(kse), MlsProviderError::KeystoreError(kse2)) => kse == kse2,
            (
                MlsProviderError::EntropySeedLengthError { expected, actual },
                MlsProviderError::EntropySeedLengthError {
                    expected: expected2,
                    actual: actual2,
                },
            ) => expected == expected2 && actual == actual2,
            (MlsProviderError::StringError(s), MlsProviderError::StringError(s2)) => s == s2,
            (MlsProviderError::RngLockPoison, MlsProviderError::RngLockPoison) => true,
            (MlsProviderError::UnsufficientEntropy, MlsProviderError::UnsufficientEntropy) => true,
            (MlsProviderError::CertificateGenerationError, MlsProviderError::CertificateGenerationError) => true,
            (MlsProviderError::UnsupportedSignatureScheme, MlsProviderError::UnsupportedSignatureScheme) => true,
            _ => false,
        }
    }
}

pub type MlsProviderResult<T> = Result<T, MlsProviderError>;
