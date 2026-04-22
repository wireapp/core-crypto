/// Result returned by MLS transport callbacks exposed through FFI.
pub type MlsTransportResult = Result<(), MlsTransportError>;

/// Errors returned by MLS transport callbacks exposed through FFI.
#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum MlsTransportError {
    /// The delivery service rejected the outgoing MLS message.
    #[error("Message Rejected: {reason}")]
    MessageRejected {
        /// The reason this message was rejected.
        reason: String,
    },
}

impl From<MlsTransportError> for core_crypto::Error {
    fn from(error: MlsTransportError) -> Self {
        match error {
            MlsTransportError::MessageRejected { reason } => {
                core_crypto::RecursiveError::mls_conversation("converting ffi transport error")(
                    core_crypto::mls::conversation::Error::MessageRejected { reason },
                )
                .into()
            }
        }
    }
}
