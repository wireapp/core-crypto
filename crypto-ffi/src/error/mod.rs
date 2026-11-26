pub(crate) mod core_crypto;
pub(crate) mod e2ei;
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
    use core_crypto::{
        ConversationId, RecursiveError, mls::conversation::Error as ConversationError,
        transaction_context::Error as TransactionError,
    };
    use rstest::rstest;

    use crate::{CoreCryptoError, MlsError};

    #[rstest]
    #[case::orphan_welcome(
        RecursiveError::context("test orphan welcome error")(ConversationError::OrphanWelcome),
        |error: &MlsError| matches!(error, MlsError::OrphanWelcome)
    )]
    #[case::conversation_already_exists(
        RecursiveError::context("test conversation exists error")(TransactionError::ConversationAlreadyExists(
            ConversationId::from("test conversation id".as_bytes()),
        )),
        |error: &MlsError| matches!(error, MlsError::ConversationAlreadyExists { .. })
    )]
    #[case::invalid_credentials(
        RecursiveError::context("test invalid credentials error")(TransactionError::InvalidCredentials(Vec::new())),
        |error: &MlsError| matches!(error, MlsError::InvalidCredentials { .. })
    )]
    fn mls_errors_map_to_the_expected_ffi_variant(
        #[case] error: RecursiveError,
        #[case] is_expected: fn(&MlsError) -> bool,
    ) {
        let mapped_error = CoreCryptoError::from(error);
        assert!(
            matches!(&mapped_error, CoreCryptoError::Mls { mls_error } if is_expected(mls_error)),
            "unexpected FFI error: {mapped_error:?}"
        );
    }

    #[test]
    fn e2ei_error_maps_to_e2ei_even_when_not_innermost() {
        // The keystore error has a source of its own, and every layer above it is transparent,
        // so the `E2eIdentityError` is not the innermost link of the chain.
        let keystore_error = core_crypto_keystore::CryptoKeystoreError::TransactionLock {
            path: "test lock path".to_owned(),
            source: std::io::Error::other("test io error"),
        };
        let e2ei_error = wire_e2e_identity::E2eIdentityError::PkiEnvError(
            wire_e2e_identity::pki_env::Error::KeystoreError(keystore_error),
        );

        let mapped_error = CoreCryptoError::from(RecursiveError::context("test e2ei error")(e2ei_error));
        assert!(
            matches!(mapped_error, CoreCryptoError::E2ei { .. }),
            "expected an e2ei error, got {mapped_error:?}"
        );
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
        let orphan_welcome_error =
            RecursiveError::context("test orphan welcome error")(core_crypto::mls::conversation::Error::OrphanWelcome);

        // this conversion should trigger a log
        let _ = CoreCryptoError::from(orphan_welcome_error);

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
