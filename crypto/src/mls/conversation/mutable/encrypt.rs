//! The methods in this module are concerned with message encryption.

use openmls::prelude::MlsMessageOutBody;

use super::{ConversationMut, Result};
use crate::OpenMlsError;

impl ConversationMut {
    /// Encrypts a raw payload then serializes it to the TLS wire format.
    ///
    /// Can only be called when there is no pending commit and no pending proposal.
    ///
    /// # Arguments
    /// * `message` - the message as a byte array
    ///
    /// # Return type
    /// This method will return an encrypted TLS serialized message.
    ///
    /// # Errors
    /// If the conversation can't be found, an error will be returned. Other errors are originating
    /// from OpenMls and the KeyStore
    pub async fn encrypt_message(&mut self, message: impl AsRef<[u8]>) -> Result<Vec<u8>> {
        #[cfg(debug_assertions)]
        {
            let group = &self.group().await;
            debug_assert!(
                group.pending_commit().is_none(),
                "precondition failed; a pending commit exists"
            );
            debug_assert!(
                group.pending_proposals().next().is_none(),
                "precondition failed; a pending proposal exists"
            );
        }

        let backend = self.crypto_provider().await?;
        let credential = self.credential().await?;
        let signer = credential.signature_key();

        self.mutate_group(async |_, group, _| {
            let encrypted = group
                .create_message(&backend, signer, message.as_ref())
                .map_err(OpenMlsError::wrap("creating encrypted message"))?;
            // all application messages must be encrypted
            debug_assert!(matches!(encrypted.body, MlsMessageOutBody::PrivateMessage(_)));
            encrypted
                .to_bytes()
                .map_err(OpenMlsError::wrap("constructing byte vector of encrypted message"))
                .map_err(Into::into)
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use crate::test_utils::*;

    #[apply(all_cred_cipher)]
    async fn can_encrypt_app_message(case: TestContext) {
        let [alice, bob] = case.sessions().await;
        Box::pin(async move {
            let conversation = case.create_conversation([&alice, &bob]).await;

            let msg = b"Hello bob";
            let encrypted = conversation.guard().await.encrypt_message(msg).await.unwrap();
            assert_ne!(&msg[..], &encrypted[..]);
            let decrypted = conversation
                .guard_of(&bob)
                .await
                .decrypt_message(encrypted)
                .await
                .unwrap()
                .app_msg
                .unwrap();
            assert_eq!(&decrypted[..], &msg[..]);
        })
        .await
    }

    /// The eleven post-quantum suites, 0xF001 to 0xF00B, driven through a whole
    /// conversation: create, add, encrypt both ways. These are round trips rather
    /// than known-answer tests, since no other implementation ships these suites.
    #[rstest::rstest]
    #[case::f001(openmls::prelude::Ciphersuite::MLS_128_MLKEM768X25519_AES128GCM_SHA256_Ed25519)]
    #[case::f002(openmls::prelude::Ciphersuite::MLS_128_MLKEM768X25519_AES256GCM_SHA384_Ed25519)]
    #[case::f003(openmls::prelude::Ciphersuite::MLS_128_MLKEM768P256_AES128GCM_SHA256_P256)]
    #[case::f004(openmls::prelude::Ciphersuite::MLS_128_MLKEM768P256_AES256GCM_SHA384_P256)]
    #[case::f005(openmls::prelude::Ciphersuite::MLS_192_MLKEM1024P384_AES256GCM_SHA384_P384)]
    #[case::f006(openmls::prelude::Ciphersuite::MLS_128_MLKEM768_AES256GCM_SHA384_P256)]
    #[case::f007(openmls::prelude::Ciphersuite::MLS_192_MLKEM1024_AES256GCM_SHA384_P384)]
    #[case::f008(openmls::prelude::Ciphersuite::MLS_192_MLKEM768_AES256GCM_SHA384_MLDSA65)]
    #[case::f009(openmls::prelude::Ciphersuite::MLS_256_MLKEM1024_AES256GCM_SHA384_MLDSA87)]
    #[case::f00a(openmls::prelude::Ciphersuite::MLS_128_MLKEM768_AES256GCM_SHA384_Ed25519)]
    #[case::f00b(openmls::prelude::Ciphersuite::MLS_128_MLKEM768X25519_CHACHA20POLY1305_SHA384_MLDSA44)]
    #[test_attr(macro_rules_attribute::apply(smol_macros::test))]
    async fn pq_suite_full_conversation_roundtrip(#[case] ciphersuite: openmls::prelude::Ciphersuite) {
        let case = TestContext::new(CredentialType::Basic, ciphersuite);
        let [alice, bob] = case.sessions().await;
        Box::pin(async move {
            let conversation = case.create_conversation([&alice, &bob]).await;
            assert_eq!(conversation.member_count().await, 2);

            let msg = b"Hello bob, this is a post-quantum greeting";
            let encrypted = conversation.guard().await.encrypt_message(msg).await.unwrap();
            assert_ne!(&msg[..], &encrypted[..]);
            let decrypted = conversation
                .guard_of(&bob)
                .await
                .decrypt_message(encrypted)
                .await
                .unwrap()
                .app_msg
                .unwrap();
            assert_eq!(&decrypted[..], &msg[..]);

            let reply = b"Hello alice, post-quantum reply received";
            let encrypted = conversation.guard_of(&bob).await.encrypt_message(reply).await.unwrap();
            assert_ne!(&reply[..], &encrypted[..]);
            let decrypted = conversation
                .guard()
                .await
                .decrypt_message(encrypted)
                .await
                .unwrap()
                .app_msg
                .unwrap();
            assert_eq!(&decrypted[..], &reply[..]);
        })
        .await
    }

    // Ensures encrypting an application message is durable
    #[apply(all_cred_cipher)]
    async fn can_encrypt_consecutive_messages(case: TestContext) {
        let [alice, bob] = case.sessions().await;
        Box::pin(async move {
            let conversation = case.create_conversation([&alice, &bob]).await;

            let msg = b"Hello bob";
            let encrypted = conversation.guard().await.encrypt_message(msg).await.unwrap();
            assert_ne!(&msg[..], &encrypted[..]);
            let decrypted = conversation
                .guard_of(&bob)
                .await
                .decrypt_message(encrypted)
                .await
                .unwrap()
                .app_msg
                .unwrap();
            assert_eq!(&decrypted[..], &msg[..]);

            let msg = b"Hello bob again";
            let encrypted = conversation.guard().await.encrypt_message(msg).await.unwrap();
            assert_ne!(&msg[..], &encrypted[..]);
            let decrypted = conversation
                .guard_of(&bob)
                .await
                .decrypt_message(encrypted)
                .await
                .unwrap()
                .app_msg
                .unwrap();
            assert_eq!(&decrypted[..], &msg[..]);
        })
        .await
    }
}
