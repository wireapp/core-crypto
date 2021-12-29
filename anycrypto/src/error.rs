#[derive(Debug, thiserror::Error)]
pub enum MlsError {
    #[error(transparent)]
    MlsGroupError(#[from] openmls::group::MlsGroupError),
    #[error(transparent)]
    MlsErrorString(#[from] openmls::error::ErrorString),
}

#[derive(Debug, thiserror::Error)]
pub enum ProteusError {
    #[error(transparent)]
    ProteusSessionError(#[from] proteus::session::Error<Box<ProteusError>>),
    #[error(transparent)]
    ProteusDecodeError(#[from] proteus::DecodeError),
    #[error(transparent)]
    ProteusEncodeError(#[from] proteus::EncodeError),
}

#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("Couldn't find {protocol} conversation with id {conversation}")]
    ConversationNotFound {
        protocol: crate::Protocol,
        conversation: crate::central::ConversationId,
    },
    #[error(transparent)]
    KeyStoreError(#[from] core_crypto_keystore::CryptoKeystoreError),
    #[error(transparent)]
    MlsError(#[from] MlsError),
    #[error(transparent)]
    ProteusError(#[from] ProteusError),
    #[error("The requested ({0}) configuration is not contained in this package")]
    ConfigurationMismatch(crate::Protocol),
    #[error(transparent)]
    Other(#[from] eyre::Report),
}

pub type CryptoResult<T> = Result<T, CryptoError>;
