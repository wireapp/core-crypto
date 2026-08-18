/// Errors produced by the Proteus layer.
#[derive(Debug, thiserror::Error, uniffi::Error)]
#[allow(missing_docs)] // error variants are self-describing
pub enum ProteusError {
    #[error("The requested session was not found")]
    SessionNotFound,
    #[error("We already decrypted this message once")]
    DuplicateMessage,
    #[error("The remote identity has changed")]
    RemoteIdentityChanged,
    #[error("Another Proteus error occurred but the details are probably irrelevant to clients ({error_code})")]
    Other { error_code: u16 },
}

impl From<core_crypto::ProteusError> for ProteusError {
    fn from(value: core_crypto::ProteusError) -> Self {
        (&value.source).into()
    }
}

impl From<&core_crypto::ProteusErrorKind> for ProteusError {
    fn from(value: &core_crypto::ProteusErrorKind) -> Self {
        type SessionError = proteus_wasm::session::Error<core_crypto_keystore::CryptoKeystoreError>;
        match value {
            core_crypto::ProteusErrorKind::ProteusSessionError(SessionError::InternalError(
                proteus_wasm::internal::types::InternalError::NoSessionForTag,
            )) => Self::SessionNotFound,
            core_crypto::ProteusErrorKind::SessionNotFound(_) => Self::SessionNotFound,
            core_crypto::ProteusErrorKind::ProteusSessionError(SessionError::DuplicateMessage) => {
                Self::DuplicateMessage
            }
            core_crypto::ProteusErrorKind::ProteusSessionError(SessionError::RemoteIdentityChanged) => {
                Self::RemoteIdentityChanged
            }
            _ => Self::Other {
                error_code: value.error_code().unwrap_or_default(),
            },
        }
    }
}
