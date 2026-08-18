pub(crate) mod core_crypto;
pub(crate) mod mls;
pub(crate) mod mls_transport;
#[cfg(feature = "proteus")]
pub(crate) mod proteus;

/// The primary error type for CoreCrypto.
pub type CoreCryptoError = core_crypto::CoreCryptoError;

/// A result type that uses `CoreCryptoError` as the default error type.
pub type CoreCryptoResult<T, E = CoreCryptoError> = Result<T, E>;

/// Prepare and dispatch a log message reporting this error.
///
/// We want to ensure consistent logging every time we pass a log message across the FFI boundary,
/// as we cannot guarantee the method, format, or existence of error logging once the result crosses.
/// Unfortunately, as there is no single point at which we convert internal errors to trans-ffi
/// errors, we need to extract the logging procedure and ensure it's called at each relevant point.
///
/// This has the further disadvantage that we have very little context information at the point of
/// logging. We'll try this out for now anyway; if it turns out that we need to add more tracing
/// in the future, we can figure out our techniques then.
fn log_error(error: &dyn std::error::Error) {
    // we exclude the original error message from the chain
    let chain = {
        let mut error = error;
        let mut chain = Vec::new();
        while let Some(inner) = error.source() {
            chain.push(inner.to_string());
            error = inner;
        }
        chain
    };
    let msg = error.to_string();
    let err = serde_json::json!({"msg": msg, "chain": chain});
    // even though there exists a `:err` formatter, it only captures the top-level
    // message from the error, so it's still worth building our own inner error formatter
    // and using serde here
    log::error!(target: "core-crypto", err:serde; "returning this error across ffi");
}

#[cfg(test)]
mod tests {
    use core_crypto::{ConversationId, RecursiveError};

    use crate::{CoreCryptoError, MlsError};

    #[test]
    fn test_mls_error_mapping() {
        let duplicate_message_error = RecursiveError::context("test duplicate message error")(
            core_crypto::mls::conversation::Error::DuplicateMessage,
        );
        let mapped_error = CoreCryptoError::from(duplicate_message_error);
        assert!(matches!(
            mapped_error,
            CoreCryptoError::Mls {
                mls_error: MlsError::DuplicateMessage
            }
        ));

        let conversation_exists_error = RecursiveError::context("test conversation exists error")(
            core_crypto::transaction_context::Error::ConversationAlreadyExists(ConversationId::from(
                "test conversation id".as_bytes(),
            )),
        );
        let mapped_error = CoreCryptoError::from(conversation_exists_error);
        assert!(matches!(
            mapped_error,
            CoreCryptoError::Mls {
                mls_error: MlsError::ConversationAlreadyExists { conversation_id: _ }
            }
        ));
    }

    #[cfg(feature = "proteus")]
    #[test]
    fn test_proteus_error_mapping() {
        use core_crypto::{ProteusError, ProteusErrorKind};

        use crate::ProteusError as ProteusErrorFfi;

        let session_not_found_eror = RecursiveError::context("recursive error wrapping core crypto error")(
            core_crypto::Error::Proteus(ProteusError::wrap("recursive error wrapping session error")(
                ProteusErrorKind::SessionNotFound("test_session_id".to_owned()),
            )),
        );

        let mapped_error = CoreCryptoError::from(session_not_found_eror);

        assert!(matches!(
            mapped_error,
            CoreCryptoError::Proteus {
                exception: ProteusErrorFfi::SessionNotFound
            }
        ));
    }

    #[test]
    fn test_recursive_error_is_logged_when_converted() {
        testing_logger::setup();
        let duplicate_message_error = RecursiveError::context("test duplicate message error")(
            core_crypto::mls::conversation::Error::DuplicateMessage,
        );

        // this conversion should trigger a log
        let _ = CoreCryptoError::from(duplicate_message_error);

        testing_logger::validate(|captured_logs| {
            assert!(
                captured_logs.iter().any(|log| log.level == log::Level::Error
                    && log.target == "core-crypto"
                    && log.body.contains("returning this error across ffi")),
                "log message did not appear within the captured logs"
            )
        });
    }
}
