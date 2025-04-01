use crate::{Ciphersuite, Ciphersuites, ClientId, CoreCrypto, CoreCryptoError, CoreCryptoResult, CredentialType};

pub mod context;
mod epoch_observer;

#[cfg(test)]
mod tests {
    use crate::{DatabaseKey, MlsError};

    use super::*;
    use core_crypto::{LeafError, RecursiveError};

    #[test]
    fn test_error_mapping() {
        let duplicate_message_error = RecursiveError::mls_conversation("test duplicate message error")(
            core_crypto::mls::conversation::Error::DuplicateMessage,
        );
        let mapped_error = CoreCryptoError::from(duplicate_message_error);
        assert!(matches!(mapped_error, CoreCryptoError::Mls(MlsError::DuplicateMessage)));

        let conversation_exists_error = RecursiveError::mls_conversation("test conversation exists error")(
            core_crypto::mls::conversation::Error::Leaf(LeafError::ConversationAlreadyExists(
                "test conversation id".into(),
            )),
        );
        let mapped_error = CoreCryptoError::from(conversation_exists_error);
        assert!(matches!(
            mapped_error,
            CoreCryptoError::Mls(MlsError::ConversationAlreadyExists(_))
        ));
    }

    #[tokio::test]
    async fn test_error_is_logged() {
        testing_logger::setup();
        // we shouldn't be able to create a SQLite DB in `/root` unless we are running this test as root
        // Don't do that!
        let key = DatabaseKey(core_crypto_keystore::DatabaseKey::generate());
        let result = CoreCrypto::new("/root/asdf".into(), key, None, None, None, None).await;
        assert!(
            result.is_err(),
            "result must be an error in order to verify that something was logged"
        );
        testing_logger::validate(|captured_logs| {
            assert!(
                captured_logs.iter().any(|log| log.level == log::Level::Warn
                    && log.target == "core-crypto"
                    && log.body.contains("returning this error across ffi")),
                "log message did not appear within the captured logs"
            )
        });
    }
}
