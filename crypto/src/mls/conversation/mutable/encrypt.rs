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

    /// The official SHAKE256 PQ suites (0xF001-0xF009), now driven end to end by the
    /// SHAKE256 one-shot key schedule. One classical-signature variant (Ed25519, 0xF001)
    /// and one ML-DSA variant (ML-DSA-65, 0xF008), so a full PQ group gets exercised.
    #[rstest::rstest]
    #[case::ed25519(openmls::prelude::Ciphersuite::MLS_128_MLKEM768X25519_AES128GCM_SHA256_Ed25519)]
    #[case::mldsa65(openmls::prelude::Ciphersuite::MLS_192_MLKEM768_AES256GCM_SHA384_MLDSA65)]
    #[test_attr(macro_rules_attribute::apply(smol_macros::test))]
    async fn official_pq_suite_full_conversation_roundtrip(#[case] ciphersuite: openmls::prelude::Ciphersuite) {
        let case = TestContext::new(CredentialType::Basic, ciphersuite);
        let [alice, bob] = case.sessions().await;
        Box::pin(async move {
            // create + add: alice creates the conversation and invites bob
            let conversation = case.create_conversation([&alice, &bob]).await;
            assert_eq!(conversation.member_count().await, 2);

            // app-message round-trip: alice -> bob
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

            // app-message round-trip: bob -> alice
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
