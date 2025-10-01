//! This table summarizes when a MLS group can create a commit or proposal:
//!
//! | can create handshake ? | 0 pend. Commit | 1 pend. Commit |
//! |------------------------|----------------|----------------|
//! | 0 pend. Proposal       | ✅              | ❌              |
//! | 1+ pend. Proposal      | ✅              | ❌              |

use openmls::prelude::MlsMessageOut;

use super::{Error, Result};
use crate::MlsGroupInfoBundle;

/// Returned when a commit is created
#[derive(Debug, Clone)]
pub struct MlsCommitBundle {
    /// A welcome message if there are pending Add proposals
    pub welcome: Option<MlsMessageOut>,
    /// The commit message
    pub commit: MlsMessageOut,
    /// `GroupInfo` if the commit is merged
    pub group_info: MlsGroupInfoBundle,
    /// An encrypted message to fan out to all other conversation members in the new epoch
    pub encrypted_message: Option<Vec<u8>>,
}

impl MlsCommitBundle {
    /// Serializes both wrapped objects into TLS and return them as a tuple of byte arrays.
    /// 0 -> welcome
    /// 1 -> message
    /// 2 -> public group state
    #[allow(clippy::type_complexity)]
    pub fn to_bytes_triple(self) -> Result<(Option<Vec<u8>>, Vec<u8>, MlsGroupInfoBundle)> {
        use openmls::prelude::TlsSerializeTrait as _;
        let welcome = self
            .welcome
            .as_ref()
            .map(|w| {
                w.tls_serialize_detached()
                    .map_err(Error::tls_serialize("serialize welcome"))
            })
            .transpose()?;
        let commit = self
            .commit
            .tls_serialize_detached()
            .map_err(Error::tls_serialize("serialize commit"))?;
        Ok((welcome, commit, self.group_info))
    }
}

#[cfg(test)]
mod tests {
    use itertools::Itertools;
    use openmls::prelude::SignaturePublicKey;

    use super::{Error, *};
    use crate::{
        mls::conversation::{Conversation as _, ConversationWithMls as _},
        test_utils::*,
        transaction_context::Error as TransactionError,
    };

    mod transport {
        use std::sync::Arc;

        use super::*;

        #[apply(all_cred_cipher)]
        async fn retry_should_work(case: TestContext) {
            let [alice, bob, charlie] = case.sessions().await;
            Box::pin(async move {
                // Create conversation
                let conversation = case.create_conversation([&alice, &bob]).await;

                // Bob produces a commit that Alice will receive only after she tried sending a commit
                let commit = conversation.acting_as(&bob).await.update().await;
                let bob_epoch = commit.conversation().guard_of(&bob).await.epoch().await;
                assert_eq!(2, bob_epoch);
                let alice_epoch = commit.conversation().guard_of(&alice).await.epoch().await;
                assert_eq!(1, alice_epoch);
                let intermediate_commit = commit.message();
                // Next time a commit is sent, process the intermediate commit and return retry, success the second time
                let retry_provider = Arc::new(
                    CoreCryptoTransportRetrySuccessProvider::default().with_intermediate_commits(
                        alice.clone(),
                        &[intermediate_commit],
                        commit.conversation().id(),
                    ),
                );

                alice.replace_transport(retry_provider.clone()).await;

                // Send two commits and process them on bobs side
                // For this second commit, the retry provider will first return retry and
                // then success, but now without an intermediate commit
                let conversation = commit.finish().advance_epoch().await.invite_notify([&charlie]).await;

                // Retry should have been returned twice
                assert_eq!(retry_provider.retry_count().await, 2);
                // Success should have been returned twice
                assert_eq!(retry_provider.success_count().await, 2);

                // Group is still in valid state
                assert!(conversation.is_functional_and_contains([&alice, &bob]).await);
            })
            .await;
        }
    }

    mod add_members {
        use std::sync::Arc;

        use super::*;

        #[apply(all_cred_cipher)]
        async fn can_add_members_to_conversation(case: TestContext) {
            let [alice, bob] = case.sessions().await;
            Box::pin(async move {
                let conversation = case.create_conversation([&alice]).await;
                let id = conversation.id.clone();
                let bob_keypackage = bob.rand_key_package(&case).await;
                // First, abort commit transport
                alice
                    .replace_transport(Arc::<CoreCryptoTransportAbortProvider>::default())
                    .await;
                alice
                    .transaction
                    .conversation(&id)
                    .await
                    .unwrap()
                    .add_members(vec![bob_keypackage.clone()])
                    .await
                    .unwrap_err();

                // commit is not applied
                assert_eq!(conversation.member_count().await, 1);

                alice
                    .replace_transport(Arc::<CoreCryptoTransportSuccessProvider>::default())
                    .await;

                let conversation = conversation.invite_notify([&bob]).await;

                assert_eq!(*conversation.id(), id);
                assert_eq!(
                    conversation
                        .guard()
                        .await
                        .conversation()
                        .await
                        .group
                        .group_id()
                        .as_slice(),
                    id.as_ref()
                );
                assert_eq!(conversation.member_count().await, 2);
                assert!(conversation.is_functional_and_contains([&alice, &bob]).await);
            })
            .await
        }

        #[apply(all_cred_cipher)]
        async fn should_return_valid_welcome(case: TestContext) {
            let [alice, bob] = case.sessions().await;
            Box::pin(async move {
                let conversation = case.create_conversation([&alice, &bob]).await;
                assert!(conversation.is_functional_and_contains([&alice, &bob]).await);
            })
            .await
        }

        #[apply(all_cred_cipher)]
        async fn should_return_valid_group_info(case: TestContext) {
            let [alice, bob, guest] = case.sessions().await;
            Box::pin(async move {
                let conversation = case.create_conversation([&alice, &bob]).await;
                let commit_bundle = alice.mls_transport().await.latest_commit_bundle().await;
                let group_info = commit_bundle.group_info.get_group_info();
                let conversation = conversation
                    .external_join_via_group_info_notify(&guest, group_info)
                    .await;
                assert!(conversation.is_functional_and_contains([&alice, &bob, &guest]).await);
            })
            .await
        }
    }

    mod remove_members {
        use super::*;

        #[apply(all_cred_cipher)]
        async fn alice_can_remove_bob_from_conversation(case: TestContext) {
            let [alice, bob] = case.sessions().await;
            Box::pin(async move {
                let conversation = case.create_conversation([&alice, &bob]).await.remove_notify(&bob).await;
                let id = conversation.id().clone();

                let MlsCommitBundle { welcome, .. } = alice.mls_transport().await.latest_commit_bundle().await;
                assert!(welcome.is_none());

                assert_eq!(conversation.member_count().await, 1);

                // But has been removed from the conversation
                assert!(matches!(
                bob.transaction.conversation(&id).await.unwrap_err(),
                TransactionError::Leaf(crate::LeafError::ConversationNotFound(ref i))
                    if i == &id
                ));
                assert!(!conversation.can_talk(&alice, &bob).await);
            })
            .await;
        }

        #[apply(all_cred_cipher)]
        async fn should_return_valid_welcome(case: TestContext) {
            let [alice, bob, guest] = case.sessions().await;
            Box::pin(async move {
                let conversation = case
                    .create_conversation([&alice, &bob])
                    .await
                    .invite_proposal_notify(&guest)
                    .await
                    .remove_notify(&bob)
                    .await;

                assert!(conversation.is_functional_and_contains([&alice, &guest]).await);
                // because Bob has been removed from the group
                assert!(!conversation.can_talk(&alice, &bob).await);
            })
            .await;
        }

        #[apply(all_cred_cipher)]
        async fn should_return_valid_group_info(case: TestContext) {
            let [alice, bob, guest] = case.sessions().await;
            Box::pin(async move {
                let conversation = case.create_conversation([&alice, &bob]).await.remove_notify(&bob).await;
                let commit_bundle = alice.mls_transport().await.latest_commit_bundle().await;
                let group_info = commit_bundle.group_info.get_group_info();
                let conversation = conversation
                    .external_join_via_group_info_notify(&guest, group_info)
                    .await;

                assert!(conversation.is_functional_and_contains([&alice, &guest]).await);
                // because Bob has been removed from the group
                assert!(!conversation.can_talk(&alice, &bob).await);
            })
            .await;
        }
    }

    mod update_keying_material {
        use super::*;

        #[apply(all_cred_cipher)]
        async fn should_succeed(case: TestContext) {
            let [alice, bob] = case.sessions().await;
            Box::pin(async move {
                let conversation = case.create_conversation([&alice, &bob]).await;
                let init_count = alice.transaction.count_entities().await;

                let bob_keys = conversation
                    .guard_of(&bob)
                    .await
                    .conversation()
                    .await
                    .encryption_keys()
                    .collect::<Vec<Vec<u8>>>();
                let alice_keys = conversation
                    .guard()
                    .await
                    .conversation()
                    .await
                    .encryption_keys()
                    .collect::<Vec<Vec<u8>>>();
                assert!(alice_keys.iter().all(|a_key| bob_keys.contains(a_key)));

                let alice_key = conversation.encryption_public_key().await;

                // proposing the key update for alice
                let conversation = conversation.update_notify().await;
                let MlsCommitBundle { welcome, .. } = alice.mls_transport().await.latest_commit_bundle().await;
                assert!(welcome.is_none());

                let alice_new_keys = conversation
                    .guard()
                    .await
                    .conversation()
                    .await
                    .encryption_keys()
                    .collect::<Vec<Vec<u8>>>();
                assert!(!alice_new_keys.contains(&alice_key));

                let bob_new_keys = conversation
                    .guard_of(&bob)
                    .await
                    .conversation()
                    .await
                    .encryption_keys()
                    .collect::<Vec<Vec<u8>>>();
                assert!(alice_new_keys.iter().all(|a_key| bob_new_keys.contains(a_key)));

                // ensuring both can encrypt messages
                assert!(conversation.is_functional_and_contains([&alice, &bob]).await);

                // make sure inline update commit + merge does not leak anything
                // that's obvious since no new encryption keypair is created in this case
                let final_count = alice.transaction.count_entities().await;
                assert_eq!(init_count, final_count);
            })
            .await;
        }

        #[apply(all_cred_cipher)]
        async fn should_create_welcome_for_pending_add_proposals(case: TestContext) {
            let [alice, bob, charlie] = case.sessions().await;
            Box::pin(async move {
                let conversation = case.create_conversation([&alice, &bob]).await;

                let bob_keys = conversation
                    .guard_of(&bob)
                    .await
                    .conversation()
                    .await
                    .signature_keys()
                    .collect::<Vec<SignaturePublicKey>>();
                let alice_keys = conversation
                    .guard()
                    .await
                    .conversation()
                    .await
                    .signature_keys()
                    .collect::<Vec<SignaturePublicKey>>();

                // checking that the members on both sides are the same
                assert!(alice_keys.iter().all(|a_key| bob_keys.contains(a_key)));

                let alice_key = conversation.encryption_public_key().await;

                // proposing adding charlie
                let conversation = conversation.invite_proposal_notify(&charlie).await;

                assert!(
                    conversation
                        .guard()
                        .await
                        .conversation()
                        .await
                        .encryption_keys()
                        .contains(&alice_key)
                );

                // The add proposal hasn't been committed yet
                assert_eq!(conversation.member_count().await, 2);

                // performing an update on Alice's key. this should generate a welcome for Charlie
                let conversation = conversation.update_notify().await;
                let MlsCommitBundle { welcome, .. } = alice.mls_transport().await.latest_commit_bundle().await;
                assert!(welcome.is_some());
                assert!(
                    !conversation
                        .guard()
                        .await
                        .conversation()
                        .await
                        .encryption_keys()
                        .contains(&alice_key)
                );

                assert_eq!(conversation.member_count().await, 3);

                let alice_new_keys = conversation
                    .guard()
                    .await
                    .conversation()
                    .await
                    .encryption_keys()
                    .collect::<Vec<Vec<u8>>>();
                assert!(!alice_new_keys.contains(&alice_key));

                let bob_new_keys = conversation
                    .guard_of(&bob)
                    .await
                    .conversation()
                    .await
                    .encryption_keys()
                    .collect::<Vec<Vec<u8>>>();
                assert!(alice_new_keys.iter().all(|a_key| bob_new_keys.contains(a_key)));

                // ensure all parties can encrypt messages
                assert!(conversation.is_functional_and_contains([&alice, &bob, &charlie]).await);
            })
            .await;
        }

        #[apply(all_cred_cipher)]
        async fn should_return_valid_welcome(case: TestContext) {
            let [alice, bob, guest] = case.sessions().await;
            Box::pin(async move {
                let conversation = case
                    .create_conversation([&alice, &bob])
                    .await
                    .invite_proposal_notify(&guest)
                    .await
                    .update_notify()
                    .await;

                assert!(conversation.is_functional_and_contains([&alice, &bob, &guest]).await);
            })
            .await;
        }

        #[apply(all_cred_cipher)]
        async fn should_return_valid_group_info(case: TestContext) {
            let [alice, bob, guest] = case.sessions().await;
            Box::pin(async move {
                let conversation = case.create_conversation([&alice, &bob]).await.update_notify().await;

                let group_info = alice.mls_transport().await.latest_group_info().await;
                let group_info = group_info.get_group_info();

                let conversation = conversation
                    .external_join_via_group_info_notify(&guest, group_info)
                    .await;
                assert!(conversation.is_functional_and_contains([&alice, &bob, &guest]).await);
            })
            .await;
        }
    }

    mod commit_pending_proposals {
        use super::*;

        #[apply(all_cred_cipher)]
        async fn should_create_a_commit_out_of_self_pending_proposals(case: TestContext) {
            let [alice, bob] = case.sessions().await;
            Box::pin(async move {
                let conversation = case
                    .create_conversation([&alice])
                    .await
                    .advance_epoch()
                    .await
                    .invite_proposal_notify(&bob)
                    .await;

                assert!(conversation.has_pending_proposals().await);
                assert_eq!(conversation.member_count().await, 1);

                let conversation = conversation.commit_pending_proposals_notify().await;
                assert_eq!(conversation.member_count().await, 2);

                assert!(conversation.is_functional_and_contains([&alice, &bob]).await);
            })
            .await;
        }

        #[apply(all_cred_cipher)]
        async fn should_create_a_commit_out_of_pending_proposals_by_ref(case: TestContext) {
            let [alice, bob, charlie] = case.sessions().await;
            Box::pin(async move {
                // Bob invites charlie
                let conversation = case
                    .create_conversation([&alice, &bob])
                    .await
                    .acting_as(&bob)
                    .await
                    .invite_proposal_notify(&charlie)
                    .await
                    .acting_as(&bob)
                    .await;

                assert!(conversation.has_pending_proposals().await);
                assert_eq!(conversation.member_count().await, 2);

                // Alice commits the proposal
                let conversation = conversation.commit_pending_proposals_notify().await;
                assert_eq!(conversation.member_count().await, 3);

                assert!(conversation.is_functional_and_contains([&alice, &bob, &charlie]).await);
            })
            .await;
        }

        #[apply(all_cred_cipher)]
        async fn should_return_valid_welcome(case: TestContext) {
            let [alice, bob] = case.sessions().await;
            Box::pin(async move {
                let conversation = case
                    .create_conversation([&alice])
                    .await
                    .invite_proposal_notify(&bob)
                    .await
                    .commit_pending_proposals_notify()
                    .await;

                assert!(conversation.is_functional_and_contains([&alice, &bob]).await);
            })
            .await;
        }

        #[apply(all_cred_cipher)]
        async fn should_return_valid_group_info(case: TestContext) {
            let [alice, bob, guest] = case.sessions().await;
            Box::pin(async move {
                let conversation = case
                    .create_conversation([&alice])
                    .await
                    .invite_proposal_notify(&bob)
                    .await
                    .commit_pending_proposals_notify()
                    .await;
                let commit_bundle = alice.mls_transport().await.latest_commit_bundle().await;
                let group_info = commit_bundle.group_info.get_group_info();
                let conversation = conversation
                    .external_join_via_group_info_notify(&guest, group_info)
                    .await;

                assert!(conversation.is_functional_and_contains([&alice, &bob, &guest]).await);
            })
            .await;
        }
    }

    mod delivery_semantics {
        use super::*;

        #[apply(all_cred_cipher)]
        async fn should_prevent_out_of_order_commits(case: TestContext) {
            let [alice, bob] = case.sessions().await;
            Box::pin(async move {
                let conversation = case.create_conversation([&alice, &bob]).await;
                let id = conversation.id().clone();

                let commit_guard = conversation.update().await;
                let commit1 = commit_guard.message();
                let commit1 = commit1.to_bytes().unwrap();

                let commit_guard = commit_guard.finish().update().await;
                let commit2 = commit_guard.message();
                let commit2 = commit2.to_bytes().unwrap();

                // fails when a commit is skipped
                let out_of_order = bob
                    .transaction
                    .conversation(&id)
                    .await
                    .unwrap()
                    .decrypt_message(&commit2)
                    .await;
                assert!(matches!(out_of_order.unwrap_err(), Error::BufferedFutureMessage { .. }));

                // works in the right order though
                // NB: here 'commit2' has been buffered so it is also applied when we decrypt commit1
                bob.transaction
                    .conversation(&id)
                    .await
                    .unwrap()
                    .decrypt_message(&commit1)
                    .await
                    .unwrap();

                // and then fails again when trying to decrypt a commit with an epoch in the past
                let past_commit = bob
                    .transaction
                    .conversation(&id)
                    .await
                    .unwrap()
                    .decrypt_message(&commit1)
                    .await;
                assert!(matches!(past_commit.unwrap_err(), Error::StaleCommit));
            })
            .await;
        }

        #[apply(all_cred_cipher)]
        async fn should_prevent_replayed_encrypted_handshake_messages(case: TestContext) {
            if !case.is_pure_ciphertext() {
                return;
            }

            let [alice, bob] = case.sessions().await;
            Box::pin(async move {
                let conversation = case.create_conversation([&alice, &bob]).await;

                let proposal_guard = conversation.update_proposal().await;
                let proposal_replay = proposal_guard.message();

                // replayed encrypted proposal should fail
                let conversation = proposal_guard.notify_members().await;
                assert!(matches!(
                    conversation
                        .guard_of(&bob)
                        .await
                        .decrypt_message(proposal_replay.to_bytes().unwrap())
                        .await
                        .unwrap_err(),
                    Error::DuplicateMessage
                ));

                let commit_guard = conversation.update().await;
                let commit_replay = commit_guard.message();

                // replayed encrypted commit should fail
                let conversation = commit_guard.notify_members().await;
                assert!(matches!(
                    conversation
                        .guard_of(&bob)
                        .await
                        .decrypt_message(commit_replay.to_bytes().unwrap())
                        .await
                        .unwrap_err(),
                    Error::StaleCommit
                ));
            })
            .await;
        }
    }
}
