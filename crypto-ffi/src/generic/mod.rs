// Wire
// Copyright (C) 2022 Wire Swiss GmbH

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with this program. If not, see http://www.gnu.org/licenses/.

use crate::{Ciphersuite, Ciphersuites, ClientId, CoreCrypto, CoreCryptoError, CoreCryptoResult, CredentialType};

pub mod context;
mod epoch_observer;

#[cfg(test)]
mod tests {
    use crate::MlsError;

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
        let result = CoreCrypto::new("/root/asdf".into(), "key".into(), None, None, None, None).await;
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
