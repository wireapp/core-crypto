/// A Proteus operation failed, but we captured some context about how it did so
pub type ProteusError = super::wrapper::WrappedContextualError<ProteusErrorKind>;

/// This error can never be constructed when compiled without proteus.
#[cfg(not(feature = "proteus"))]
#[derive(Debug, thiserror::Error)]
pub enum ProteusErrorKind {}

/// Proteus produces these kinds of error
#[cfg(feature = "proteus")]
#[derive(Debug, thiserror::Error)]
pub enum ProteusErrorKind {
    /// Error when decoding CBOR and/or decrypting Proteus messages
    #[error(transparent)]
    ProteusDecodeError(#[from] proteus_wasm::DecodeError),
    /// Error when encoding CBOR and/or decrypting Proteus messages
    #[error(transparent)]
    ProteusEncodeError(#[from] proteus_wasm::EncodeError),
    /// Various internal Proteus errors
    #[error(transparent)]
    ProteusInternalError(#[from] proteus_wasm::error::ProteusError),
    /// Error when there's a critical error within a proteus Session
    #[error(transparent)]
    ProteusSessionError(#[from] proteus_wasm::session::Error<core_crypto_keystore::CryptoKeystoreError>),
    /// Common errors we generate
    #[error("{0}")]
    Leaf(#[from] crate::LeafError),
}

impl ProteusErrorKind {
    #[cfg(feature = "proteus")]
    fn proteus_error_code(&self) -> Option<proteus_traits::ProteusErrorKind> {
        use proteus_traits::ProteusErrorCode as _;
        let mut out = match self {
            ProteusErrorKind::ProteusDecodeError(decode_error) => Some(decode_error.code()),
            ProteusErrorKind::ProteusEncodeError(encode_error) => Some(encode_error.code()),
            ProteusErrorKind::ProteusInternalError(proteus_error) => Some(proteus_error.code()),
            ProteusErrorKind::ProteusSessionError(session_error) => Some(session_error.code()),
            ProteusErrorKind::Leaf(crate::LeafError::ConversationNotFound(_)) => {
                Some(proteus_traits::ProteusErrorKind::SessionStateNotFoundForTag)
            }
            ProteusErrorKind::Leaf(_) => None,
        };
        if out == Some(proteus_traits::ProteusErrorKind::None) {
            out = None;
        }
        out
    }
    /// Returns the proteus error code
    pub fn error_code(&self) -> Option<u16> {
        #[cfg(feature = "proteus")]
        {
            self.proteus_error_code().map(|code| code as u16)
        }

        #[cfg(not(feature = "proteus"))]
        {
            None
        }
    }
}
