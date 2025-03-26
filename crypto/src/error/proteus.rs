/// A Proteus operation failed, but we captured some context about how it did so
pub type ProteusError = super::wrapper::WrappedContextualError<ProteusErrorKind>;

/// Proteus produces these kinds of error
#[derive(Debug, thiserror::Error, strum::IntoStaticStr)]
pub enum ProteusErrorKind {
    #[cfg(feature = "proteus")]
    #[error(transparent)]
    /// Error when decoding CBOR and/or decrypting Proteus messages
    ProteusDecodeError(#[from] proteus_wasm::DecodeError),
    #[cfg(feature = "proteus")]
    #[error(transparent)]
    /// Error when encoding CBOR and/or decrypting Proteus messages
    ProteusEncodeError(#[from] proteus_wasm::EncodeError),
    #[cfg(feature = "proteus")]
    #[error(transparent)]
    /// Various internal Proteus errors
    ProteusInternalError(#[from] proteus_wasm::error::ProteusError),
    #[cfg(feature = "proteus")]
    #[error(transparent)]
    /// Error when there's a critical error within a proteus Session
    ProteusSessionError(#[from] proteus_wasm::session::Error<core_crypto_keystore::CryptoKeystoreError>),
    /// Common errors we generate
    #[cfg(feature = "proteus")]
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
            ProteusErrorKind::Leaf(_) => None,
        };
        if out == Some(proteus_traits::ProteusErrorKind::None) {
            out = None;
        }
        out
    }
    /// Returns the proteus error code
    pub fn error_code(&self) -> Option<u16> {
        cfg_if::cfg_if! {
            if #[cfg(feature = "proteus")] {
                self.proteus_error_code().map(|code| code as u16)
            } else {
                None
            }
        }
    }
}
