#[derive(Debug, thiserror::Error)]
#[cfg_attr(target_family = "wasm", derive(strum::AsRefStr))]
#[cfg_attr(not(target_family = "wasm"), derive(uniffi::Error))]
pub enum ProteusError {
    #[error("The requested session was not found")]
    SessionNotFound,
    #[error("We already decrypted this message once")]
    DuplicateMessage,
    #[error("The remote identity has changed")]
    RemoteIdentityChanged,
    #[error("Another Proteus error occurred but the details are probably irrelevant to clients ({0})")]
    Other(u16),
}

impl ProteusError {
    pub fn from_error_code(code: impl Into<Option<u16>>) -> Option<Self> {
        let code = code.into()?;
        if code == 0 {
            return None;
        }

        match code {
            102 => Self::SessionNotFound,
            204 => Self::RemoteIdentityChanged,
            209 => Self::DuplicateMessage,
            _ => Self::Other(code),
        }
        .into()
    }

    pub fn error_code(&self) -> u16 {
        match self {
            Self::SessionNotFound => 102,
            Self::RemoteIdentityChanged => 204,
            Self::DuplicateMessage => 209,
            Self::Other(code) => *code,
        }
    }
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
            core_crypto::ProteusErrorKind::ProteusSessionError(SessionError::DuplicateMessage) => {
                Self::DuplicateMessage
            }
            core_crypto::ProteusErrorKind::ProteusSessionError(SessionError::RemoteIdentityChanged) => {
                Self::RemoteIdentityChanged
            }
            _ => Self::Other(value.error_code().unwrap_or_default()),
        }
    }
}
