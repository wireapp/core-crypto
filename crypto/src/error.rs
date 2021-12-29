#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("Couldn't find conversation with id {0}")]
    ConversationNotFound(crate::ConversationId),
    #[error(transparent)]
    KeyStoreError(#[from] core_crypto_keystore::CryptoKeystoreError),
    #[error(transparent)]
    MlsError(#[from] MlsError),
    #[error(transparent)]
    Other(#[from] eyre::Report),
}

pub type CryptoResult<T> = Result<T, CryptoError>;

/// MLS-specific error wrapper
#[derive(Debug, thiserror::Error)]
pub enum MlsError {
    #[error(transparent)]
    MlsValidationError(#[from] openmls::prelude::ValidationError),
    #[error(transparent)]
    MlsVerificationError(#[from] openmls::prelude::VerificationError),
    #[error(transparent)]
    MlsInvalidMessageError(#[from] openmls::prelude::InvalidMessageError),
    #[error(transparent)]
    MlsEmptyInputError(#[from] openmls::prelude::EmptyInputError),
    #[error(transparent)]
    MlsCredentialError(#[from] openmls::prelude::CredentialError),
    #[error(transparent)]
    MlsGroupError(#[from] openmls::prelude::MlsGroupError),
    #[error(transparent)]
    MlsCiphertextError(#[from] openmls::prelude::MlsCiphertextError),
    #[error(transparent)]
    MlsPlaintextError(#[from] openmls::prelude::MlsPlaintextError),
    #[error(transparent)]
    MlsErrorString(#[from] openmls::error::ErrorString),
}
