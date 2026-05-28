//! MLS groups (aka conversation) are the actual entities cementing all the participants in a
//! conversation.
//!
//! This table summarizes what operations are permitted on a group depending its state:
//! *(PP=pending proposal, PC=pending commit)*
//!
//! | can I ?   | 0 PP / 0 PC | 1+ PP / 0 PC | 0 PP / 1 PC | 1+ PP / 1 PC |
//! |-----------|-------------|--------------|-------------|--------------|
//! | encrypt   | ✅           | ❌            | ❌           | ❌            |
//! | handshake | ✅           | ✅            | ❌           | ❌            |
//! | merge     | ❌           | ❌            | ✅           | ✅            |
//! | decrypt   | ✅           | ✅            | ✅           | ✅            |

mod commit;
mod config;
mod error;
mod group_info;
mod id;
mod immutable;
mod mutable;
mod orphan_welcome;
mod pending;
mod welcome;

pub(crate) use pending::PendingConversation;

pub use self::{
    commit::CommitBundle,
    config::{ConversationConfiguration, CustomConfiguration, WirePolicy},
    error::{Error, Result},
    group_info::{GroupInfoBundle, GroupInfoEncryptionType, GroupInfoPayload, RatchetTreeType},
    id::{ConversationId, ConversationIdRef},
    immutable::ImmutableConversation,
    mutable::{
        ConversationMut,
        decrypt::{BufferedDecryptedMessage, DecryptedMessage},
    },
    welcome::WelcomeMessage,
};
use crate::bytes_wrapper;

bytes_wrapper!(
    /// A secret key derived from the group secret.
    ///
    /// This is intended to be used for AVS.
    #[derive(Clone)]
    SecretKey
);

bytes_wrapper!(
    /// The raw public key of an external sender.
    ///
    /// This can be used to initialize a subconversation.
    #[derive(Clone)]
    ExternalSenderKey
);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::*;

    #[apply(all_cred_cipher)]
    pub async fn create_self_conversation_should_succeed(case: TestContext) {
        let [alice] = case.sessions().await;
        Box::pin(async move {
            let conversation = case.create_conversation([&alice]).await;
            assert_eq!(1, conversation.member_count().await);
            let alice_can_send_message = conversation.guard().await.encrypt_message(b"me").await;
            assert!(alice_can_send_message.is_ok());
        })
        .await;
    }

    #[apply(all_cred_cipher)]
    pub async fn create_1_1_conversation_should_succeed(case: TestContext) {
        let [alice, bob] = case.sessions().await;
        Box::pin(async move {
            let conversation = case.create_conversation([&alice, &bob]).await;
            assert_eq!(2, conversation.member_count().await);
            assert!(conversation.is_functional_and_contains([&alice, &bob]).await);
        })
        .await;
    }

    #[apply(all_cred_cipher)]
    pub async fn create_many_people_conversation(case: TestContext) {
        const SIZE_PLUS_1: usize = GROUP_SAMPLE_SIZE + 1;
        let alice_and_friends = case.sessions::<SIZE_PLUS_1>().await;
        Box::pin(async move {
            let alice = &alice_and_friends[0];
            let conversation = case.create_conversation([alice]).await;

            let bob_and_friends = &alice_and_friends[1..];
            let conversation = conversation.invite_notify(bob_and_friends).await;

            assert_eq!(conversation.member_count().await, 1 + GROUP_SAMPLE_SIZE);
            assert!(conversation.is_functional_and_contains(&alice_and_friends).await);
        })
        .await;
    }

    mod wire_identity_getters {
        use super::Error;
        use crate::{
            ClientId, CredentialType, DeviceStatus, E2eiConversationState, mls::conversation::ImmutableConversation,
            test_utils::*,
        };

        async fn all_identities_check<const N: usize>(
            conversation: &ImmutableConversation,
            user_ids: &[String; N],
            expected_sizes: [usize; N],
        ) {
            let all_identities = conversation.get_user_identities(user_ids).await.unwrap();
            assert_eq!(all_identities.len(), N);
            for (expected_size, user_id) in expected_sizes.into_iter().zip(user_ids.iter()) {
                let alice_identities = all_identities.get(user_id).unwrap();
                assert_eq!(alice_identities.len(), expected_size);
            }
            // Not found
            let not_found = conversation
                .get_user_identities(&["aaaaaaaaaaaaa".to_string()])
                .await
                .unwrap();
            assert!(not_found.is_empty());

            // Invalid usage
            let invalid = conversation.get_user_identities(&[]).await;
            assert!(matches!(invalid.unwrap_err(), Error::CallerError(_)));
        }

        async fn check_identities_device_status<const N: usize>(
            conversation: &ImmutableConversation,
            client_ids: &[ClientId; N],
            name_status: &[(impl ToString, DeviceStatus); N],
        ) {
            let mut identities = conversation.get_device_identities(client_ids).await.unwrap();

            for (user_name, status) in name_status.iter() {
                let client_identity = identities.remove(
                    identities
                        .iter()
                        .position(|i| i.x509_identity.as_ref().unwrap().display_name == user_name.to_string())
                        .unwrap(),
                );
                assert_eq!(client_identity.status, *status);
            }
            assert!(identities.is_empty());

            assert_eq!(
                conversation.e2ei_conversation_state().await.unwrap(),
                E2eiConversationState::NotVerified
            );
        }

        // TODO: ignore this test for now, until we fix the test suite (WPB-25356)
        #[ignore]
        #[macro_rules_attribute::apply(smol_macros::test)]
        async fn should_read_device_identities() {
            let case = TestContext::default_x509();

            let [alice_android, alice_ios] = case.sessions().await;
            Box::pin(async move {
                let conversation = case.create_conversation([&alice_android, &alice_ios]).await;

                let (android_id, ios_id) = (alice_android.get_client_id().await, alice_ios.get_client_id().await);

                let mut android_ids = conversation
                    .guard()
                    .await
                    .get_device_identities(&[android_id.clone(), ios_id.clone()])
                    .await
                    .unwrap();
                android_ids.sort_by(|a, b| a.client_id.cmp(&b.client_id));
                assert_eq!(android_ids.len(), 2);
                let mut ios_ids = conversation
                    .guard_of(&alice_ios)
                    .await
                    .get_device_identities(&[android_id.clone(), ios_id.clone()])
                    .await
                    .unwrap();
                ios_ids.sort_by(|a, b| a.client_id.cmp(&b.client_id));
                assert_eq!(ios_ids.len(), 2);

                assert_eq!(android_ids, ios_ids);

                let android_identities = conversation
                    .guard()
                    .await
                    .get_device_identities(&[android_id])
                    .await
                    .unwrap();
                let android_id = android_identities.first().unwrap();
                assert_eq!(
                    android_id.client_id.as_bytes(),
                    alice_android.transaction.client_id().await.unwrap().0.as_slice()
                );

                let ios_identities = conversation
                    .guard()
                    .await
                    .get_device_identities(&[ios_id])
                    .await
                    .unwrap();
                let ios_id = ios_identities.first().unwrap();
                assert_eq!(
                    ios_id.client_id.as_bytes(),
                    alice_ios.transaction.client_id().await.unwrap().0.as_slice()
                );

                let empty_slice: &[ClientId] = &[];
                let invalid = conversation.guard().await.get_device_identities(empty_slice).await;
                assert!(matches!(invalid.unwrap_err(), Error::CallerError(_)));
            })
            .await
        }

        // TODO: ignore this test for now, until we fix the test suite (WPB-25356)
        #[ignore]
        #[macro_rules_attribute::apply(smol_macros::test)]
        async fn should_read_revoked_device() {
            let case = TestContext::default_x509();
            let rupert_user_id = uuid::Uuid::new_v4();
            let bob_user_id = uuid::Uuid::new_v4();
            let alice_user_id = uuid::Uuid::new_v4();

            let [rupert_client_id] = case.x509_client_ids_for_user(&rupert_user_id);
            let [alice_client_id] = case.x509_client_ids_for_user(&alice_user_id);
            let [bob_client_id] = case.x509_client_ids_for_user(&bob_user_id);

            let sessions = case
                .sessions_x509_with_client_ids_and_revocation(
                    [alice_client_id.clone(), bob_client_id.clone(), rupert_client_id.clone()],
                    &[rupert_user_id.to_string()],
                )
                .await;

            Box::pin(async move {
                let [alice, bob, rupert] = &sessions;
                let conversation = case.create_conversation(&sessions).await;

                let (alice_id, bob_id, rupert_id) = (
                    alice.get_client_id().await,
                    bob.get_client_id().await,
                    rupert.get_client_id().await,
                );

                let client_ids = [alice_id, bob_id, rupert_id];
                let name_status = [
                    (alice_user_id, DeviceStatus::Valid),
                    (bob_user_id, DeviceStatus::Valid),
                    (rupert_user_id, DeviceStatus::Revoked),
                ];

                // Do it a multiple times to avoid WPB-6904 happening again
                for _ in 0..2 {
                    for session in sessions.iter() {
                        let conversation = conversation.guard_of(session).await;
                        check_identities_device_status(&*conversation, &client_ids, &name_status).await;
                    }
                }
            })
            .await
        }

        #[macro_rules_attribute::apply(smol_macros::test)]
        async fn should_not_fail_when_basic() {
            let case = TestContext::default();

            let [alice_android, alice_ios] = case.sessions().await;
            Box::pin(async move {
                let conversation = case.create_conversation([&alice_android, &alice_ios]).await;

                let (android_id, ios_id) = (alice_android.get_client_id().await, alice_ios.get_client_id().await);

                let mut android_ids = conversation
                    .guard()
                    .await
                    .get_device_identities(&[android_id.clone(), ios_id.clone()])
                    .await
                    .unwrap();
                android_ids.sort();

                let mut ios_ids = conversation
                    .guard_of(&alice_ios)
                    .await
                    .get_device_identities(&[android_id, ios_id])
                    .await
                    .unwrap();
                ios_ids.sort();

                assert_eq!(ios_ids.len(), 2);
                assert_eq!(ios_ids, android_ids);

                assert!(ios_ids.iter().all(|i| {
                    matches!(i.credential_type, CredentialType::Basic)
                        && matches!(i.status, DeviceStatus::Valid)
                        && i.x509_identity.is_none()
                        && !i.thumbprint.is_empty()
                        && !i.client_id.is_empty()
                }));
            })
            .await
        }

        // TODO: ignore this test for now, until we fix the test suite (WPB-25356)
        #[ignore]
        #[macro_rules_attribute::apply(smol_macros::test)]
        async fn should_read_users() {
            let case = TestContext::default_x509();
            let [alice_android, alice_ios] = case.x509_client_ids_for_user(&uuid::Uuid::new_v4());
            let [bob_android] = case.x509_client_ids();

            let sessions = case
                .sessions_x509_with_client_ids([alice_android, alice_ios, bob_android])
                .await;

            Box::pin(async move {
                let conversation = case.create_conversation(&sessions).await;

                let nb_members = conversation.member_count().await;
                assert_eq!(nb_members, 3);

                let [alice_android, alice_ios, bob_android] = &sessions;
                assert_eq!(alice_android.get_user_id().await, alice_ios.get_user_id().await);

                // Finds both Alice's devices
                let alice_user_id = alice_android.get_user_id().await;
                let alice_identities = conversation
                    .guard()
                    .await
                    .get_user_identities(std::slice::from_ref(&alice_user_id))
                    .await
                    .unwrap();
                assert_eq!(alice_identities.len(), 1);
                let identities = alice_identities.get(&alice_user_id).unwrap();
                assert_eq!(identities.len(), 2);

                // Finds Bob only device
                let bob_user_id = bob_android.get_user_id().await;
                let bob_identities = conversation
                    .guard()
                    .await
                    .get_user_identities(std::slice::from_ref(&bob_user_id))
                    .await
                    .unwrap();
                assert_eq!(bob_identities.len(), 1);
                let identities = bob_identities.get(&bob_user_id).unwrap();
                assert_eq!(identities.len(), 1);

                let user_ids = [alice_user_id, bob_user_id];
                let expected_sizes = [2, 1];

                for session in &sessions {
                    all_identities_check(&*conversation.guard_of(session).await, &user_ids, expected_sizes).await;
                }
            })
            .await
        }
    }

    mod export_secret {
        use openmls::prelude::ExportSecretError;

        use super::*;
        use crate::OpenMlsErrorKind;

        #[apply(all_cred_cipher)]
        pub async fn can_export_secret_key(case: TestContext) {
            let [alice] = case.sessions().await;
            Box::pin(async move {
                let conversation = case.create_conversation([&alice]).await;

                let key_length = 128;
                let result = conversation.guard().await.export_secret_key(key_length).await;
                assert!(result.is_ok());
                assert_eq!(result.unwrap().len(), key_length);
            })
            .await
        }

        #[apply(all_cred_cipher)]
        pub async fn cannot_export_secret_key_invalid_length(case: TestContext) {
            let [alice] = case.sessions().await;
            Box::pin(async move {
                let conversation = case.create_conversation([&alice]).await;

                let result = conversation.guard().await.export_secret_key(usize::MAX).await;
                let error = result.unwrap_err();
                assert!(innermost_source_matches!(
                    error,
                    OpenMlsErrorKind::MlsExportSecretError(ExportSecretError::KeyLengthTooLong)
                ));
            })
            .await
        }
    }

    mod get_client_ids {
        use super::*;

        #[apply(all_cred_cipher)]
        pub async fn can_get_client_ids(case: TestContext) {
            let [alice, bob] = case.sessions().await;
            Box::pin(async move {
                let conversation = case.create_conversation([&alice]).await;

                assert_eq!(conversation.guard().await.get_client_ids().await.len(), 1);

                let conversation = conversation.invite_notify([&bob]).await;

                assert_eq!(conversation.guard().await.get_client_ids().await.len(), 2);
            })
            .await
        }
    }

    mod external_sender {
        use super::*;

        #[apply(all_cred_cipher)]
        pub async fn should_fetch_ext_sender(mut case: TestContext) {
            let [alice, external_sender] = case.sessions().await;
            Box::pin(async move {
                use core_crypto_keystore::Sha256Hash;

                let conversation = case
                    .create_conversation_with_external_sender(&external_sender, [&alice])
                    .await;

                let alice_ext_sender = conversation.guard().await.get_external_sender().await.unwrap();
                assert!(!alice_ext_sender.is_empty());
                assert_eq!(
                    Sha256Hash::hash_from(alice_ext_sender),
                    external_sender.initial_credential.public_key_hash()
                );
            })
            .await
        }
    }
}
