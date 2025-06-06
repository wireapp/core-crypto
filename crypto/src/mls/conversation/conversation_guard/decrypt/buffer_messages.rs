//! Sometimes, while still in epoch `n`, we receive messages for epoch `n + 1`.
//! This is because our DS implementation doesn't guarantee that messages arrive in order.
//! This module deals with buffering these messages until we receive the commit that advances the
//! group epoch.

use super::{RecursionPolicy, Result};
use crate::KeystoreError;
use crate::mls::conversation::{ConversationGuard, ConversationWithMls, Error};
use crate::obfuscate::Obfuscated;
use crate::prelude::MlsBufferedConversationDecryptMessage;
use core_crypto_keystore::connection::FetchFromDatabase;
use core_crypto_keystore::entities::{EntityFindParams, MlsPendingMessage};
use log::{error, info};
use openmls::framing::{MlsMessageIn, MlsMessageInBody};
use openmls_traits::OpenMlsCryptoProvider as _;
use tls_codec::Deserialize;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum MessageRestorePolicy {
    /// Retrieve and decrypt pending messages, then clear them from the keystore.
    DecryptAndClear,
    /// Clear pending messages from the keystore without decrypting them.
    ClearOnly,
}

impl ConversationGuard {
    pub(super) async fn buffer_future_message(&self, message: impl AsRef<[u8]>) -> Result<()> {
        let backend = self.crypto_provider().await?;
        let keystore = backend.keystore();
        let conversation = self.conversation().await;
        let pending_msg = MlsPendingMessage {
            foreign_id: conversation.id().clone(),
            message: message.as_ref().to_vec(),
        };
        keystore
            .save::<MlsPendingMessage>(pending_msg)
            .await
            .map_err(KeystoreError::wrap("saving pending mls message"))?;
        Ok(())
    }

    pub(super) async fn restore_and_clear_pending_messages(
        &mut self,
    ) -> Result<Option<Vec<MlsBufferedConversationDecryptMessage>>> {
        let pending_messages = self
            .restore_pending_messages(MessageRestorePolicy::DecryptAndClear)
            .await?;

        if pending_messages.is_some() {
            let conversation = self.conversation().await;
            let backend = self.crypto_provider().await?;
            info!(group_id = Obfuscated::from(conversation.id()); "Clearing all buffered messages for conversation");
            backend
                .key_store()
                .remove::<MlsPendingMessage, _>(conversation.id())
                .await
                .map_err(KeystoreError::wrap("removing MlsPendingMessage from keystore"))?;
        }

        Ok(pending_messages)
    }

    #[cfg_attr(target_family = "wasm", async_recursion::async_recursion(?Send))]
    #[cfg_attr(not(target_family = "wasm"), async_recursion::async_recursion)]
    pub(crate) async fn restore_pending_messages(
        &mut self,
        policy: MessageRestorePolicy,
    ) -> Result<Option<Vec<MlsBufferedConversationDecryptMessage>>> {
        let result = async move {
            let conversation = self.conversation().await;
            let conversation_id = conversation.id();
            let backend = self.crypto_provider().await?;
            let keystore = backend.keystore();
            if policy == MessageRestorePolicy::ClearOnly {
                if keystore
                    .find::<MlsPendingMessage>(conversation_id)
                    .await
                    .map_err(KeystoreError::wrap("finding mls pending message by group id"))?
                    .is_some()
                {
                    keystore
                        .remove::<MlsPendingMessage, _>(conversation_id)
                        .await
                        .map_err(KeystoreError::wrap("removing mls pending message"))?;
                }
                return Ok(None);
            }

            let mut pending_messages = keystore
                .find_all::<MlsPendingMessage>(EntityFindParams::default())
                .await
                .map_err(KeystoreError::wrap("finding all mls pending messages"))?
                .into_iter()
                .filter(|pm| pm.foreign_id == *conversation_id)
                .map(|m| -> Result<_> {
                    let msg = MlsMessageIn::tls_deserialize(&mut m.message.as_slice())
                        .map_err(Error::tls_deserialize("mls message in"))?;
                    let ct = match msg.body_as_ref() {
                        MlsMessageInBody::PublicMessage(m) => m.content_type(),
                        MlsMessageInBody::PrivateMessage(m) => m.content_type(),
                        _ => return Err(Error::InappropriateMessageBodyType),
                    };
                    Ok((ct as u8, msg))
                })
                .collect::<Result<Vec<_>>>()?;

            // We want to restore application messages first, then Proposals & finally Commits
            // luckily for us that's the exact same order as the [ContentType] enum
            pending_messages.sort_by(|(a, _), (b, _)| a.cmp(b));

            info!(group_id = Obfuscated::from(conversation_id); "Attempting to restore {} buffered messages", pending_messages.len());

            // Need to drop conversation to allow borrowing `self` again.
            drop(conversation);

            let mut decrypted_messages = Vec::with_capacity(pending_messages.len());
            for (_, m) in pending_messages {
                let decrypted = self
                    .decrypt_message_inner(m, RecursionPolicy::None)
                    .await?;
                decrypted_messages.push(decrypted.into());
            }

            let decrypted_messages = (!decrypted_messages.is_empty()).then_some(decrypted_messages);

            Ok(decrypted_messages)
        }
            .await;
        if let Err(e) = &result {
            error!(error:% = e; "Error restoring pending messages");
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::prelude::MlsConversationDecryptMessage;
    use crate::test_utils::*;

    #[apply(all_cred_cipher)]
    async fn can_operate_with_pending_commit_wpb_17356(case: TestContext) {
        let [alice] = case.sessions().await;
        let conversation = case.create_conversation([&alice]).await;
        // create a pending commit
        let conversation = conversation.update_unmerged().await.finish();
        let mut conversation = conversation.guard().await;
        // This should work, even though there is a pending commit!
        assert!(conversation.conversation().await.group.pending_commit().is_some());
        conversation.update_key_material().await.unwrap();
        assert!(conversation.conversation().await.group.pending_commit().is_none());
    }

    #[apply(all_cred_cipher)]
    async fn should_buffer_and_reapply_messages_after_commit_merged_for_sender(case: TestContext) {
        if case.is_pure_ciphertext() {
            // The use case tested here requires inspecting your own commit.
            // Openmls does not support this currently when protocol messages are encrypted.
            return;
        }

        let [alice, bob, charlie, debbie] = case.sessions().await;
        Box::pin(async move {
            let conversation = case.create_conversation([&alice, &bob]).await;

            // Bob creates a commit but won't merge it immediately (e.g, because his app crashes before he receives the success response from the ds)
            let unmerged_commit_guard = conversation.acting_as(&bob).await.update_unmerged().await;
            let unmerged_commit = unmerged_commit_guard.message();

            // Alice decrypts the commit...
            let conversation = unmerged_commit_guard.notify_member(&alice).await.finish();

            // ...then Alice generates new messages for this epoch
            let app_msg = conversation
                .guard()
                .await
                .encrypt_message(b"Hello Bob !")
                .await
                .unwrap();

            // Meanwhile Debbie joins the party by creating an external proposal
            let proposal_guard = conversation
                .external_join_proposal(&debbie)
                .await
                .notify_member(&alice)
                .await;
            let external_proposal = proposal_guard.message();
            let conversation = proposal_guard.finish();

            let proposal_guard = conversation.update_proposal().await;
            let proposal = proposal_guard.message();
            let conversation = proposal_guard.finish();

            // This commit will contain the invitations of charlie and debbie
            let commit_guard = conversation.invite([&charlie]).await;
            let commit = commit_guard.message();
            // This will make charlie and debbie process welcome messages
            let conversation = commit_guard.process_member_changes().await.finish();

            // And now Bob will have to decrypt those messages while he hasn't yet merged its commit
            // To add more fun, he will buffer the messages in exactly the wrong order (to make
            // sure he reapplies them in the right order afterwards)
            let messages = [commit, external_proposal, proposal]
                .into_iter()
                .map(|m| m.to_bytes().unwrap())
                .chain(std::iter::once(app_msg));
            for m in messages {
                let decrypt = conversation.guard_of(&bob).await.decrypt_message(m).await;
                assert!(matches!(decrypt.unwrap_err(), Error::BufferedFutureMessage { .. }));
            }

            // Bob should have buffered the messages
            assert_eq!(bob.transaction.count_entities().await.pending_messages, 4);

            let observer = TestEpochObserver::new();
            bob.session()
                .await
                .register_epoch_observer(observer.clone())
                .await
                .unwrap();

            // Finally, Bob receives the green light from the DS and he can merge the external commit
            let MlsConversationDecryptMessage {
                buffered_messages: Some(restored_messages),
                ..
            } = conversation
                .guard_of(&bob)
                .await
                .decrypt_message(unmerged_commit.to_bytes().unwrap())
                .await
                .unwrap()
            else {
                panic!("Alice's messages should have been restored at this point");
            };

            for (idx, msg) in restored_messages.iter().enumerate() {
                if idx == 0 {
                    // this is the application message
                    assert_eq!(msg.app_msg.as_deref(), Some("Hello Bob !".as_bytes()));
                } else {
                    assert!(msg.app_msg.is_none());
                }
            }
            let observed_epochs = observer
                .observed_epochs()
                .await
                .into_iter()
                .map(|(_conversation_id, epoch)| epoch)
                .collect::<Vec<_>>();
            dbg!(&observed_epochs);
            assert_eq!(
                observed_epochs.len(),
                2,
                "there was 1 buffered commit changing the epoch plus the outer commit changing the epoch"
            );

            assert_eq!(conversation.member_count().await, 4);
            assert!(
                conversation
                    .is_functional_and_contains([&alice, &bob, &charlie, &debbie])
                    .await
            );

            // After merging we should erase all those pending messages
            assert_eq!(bob.transaction.count_entities().await.pending_messages, 0);
        })
        .await
    }

    #[apply(all_cred_cipher)]
    async fn should_buffer_and_reapply_messages_after_commit_merged_for_receivers(case: TestContext) {
        if case.is_pure_ciphertext() {
            // The use case tested here requires inspecting your own commit.
            // Openmls does not support this currently when protocol messages are encrypted.
            return;
        }

        let [alice, bob, charlie, debbie] = case.sessions().await;
        Box::pin(async move {
            let conversation = case.create_conversation([&alice]).await;

            // Bob joins the group with an external commit...
            let commit_guard = conversation.external_join(&bob).await;
            let ext_commit = commit_guard.message();
            let conversation = commit_guard.process_member_changes().await.finish();

            // And before Alice had the chance to get the commit, Bob will create & send messages in the next epoch
            // which Alice will have to buffer until she receives the commit.
            // This simulates what the DS does with unordered messages
            let app_msg = conversation
                .guard_of(&bob)
                .await
                .encrypt_message(b"Hello Alice !")
                .await
                .unwrap();
            let proposal_guard = conversation
                .acting_as(&bob)
                .await
                .external_join_proposal(&charlie)
                .await
                .notify_member(&bob)
                .await;
            let external_proposal = proposal_guard.message();
            let conversation = proposal_guard.finish();
            let proposal_guard = conversation.acting_as(&bob).await.update_proposal().await;
            let proposal = proposal_guard.message();
            let commit_guard = proposal_guard.finish().acting_as(&bob).await.invite([&debbie]).await;
            let commit = commit_guard.message();
            let conversation = commit_guard.process_member_changes().await.finish();

            // And now Alice will have to decrypt those messages while he hasn't yet merged the commit
            // To add more fun, he will buffer the messages in exactly the wrong order (to make
            // sure he reapplies them in the right order afterwards)
            let messages = vec![commit, external_proposal, proposal]
                .into_iter()
                .map(|m| m.to_bytes().unwrap());
            for m in messages {
                let decrypt = conversation.guard().await.decrypt_message(m).await;
                assert!(matches!(decrypt.unwrap_err(), Error::BufferedFutureMessage { .. }));
            }
            let decrypt = conversation.guard().await.decrypt_message(app_msg).await;
            assert!(matches!(decrypt.unwrap_err(), Error::BufferedFutureMessage { .. }));

            // Alice should have buffered the messages
            assert_eq!(alice.transaction.count_entities().await.pending_messages, 4);

            let observer = TestEpochObserver::new();
            alice
                .session()
                .await
                .register_epoch_observer(observer.clone())
                .await
                .unwrap();

            // Finally, Alice receives the original commit for this epoch
            let original_commit = ext_commit.to_bytes().unwrap();
            let MlsConversationDecryptMessage {
                buffered_messages: Some(restored_messages),
                ..
            } = conversation
                .guard()
                .await
                .decrypt_message(original_commit)
                .await
                .unwrap()
            else {
                panic!("Alice's messages should have been restored at this point");
            };
            for (idx, msg) in restored_messages.into_iter().enumerate() {
                if idx == 0 {
                    assert_eq!(msg.app_msg.as_deref(), Some(b"Hello Alice !" as _));
                } else {
                    assert!(msg.app_msg.is_none());
                }
            }

            let observed_epochs = observer
                .observed_epochs()
                .await
                .into_iter()
                .map(|(_conversation_id, epoch)| epoch)
                .collect::<Vec<_>>();
            dbg!(&observed_epochs);
            assert_eq!(
                observed_epochs.len(),
                2,
                "there was 1 buffered commit changing the epoch plus the outer commit changing the epoch"
            );

            assert_eq!(conversation.member_count().await, 4);
            assert!(
                conversation
                    .is_functional_and_contains([&alice, &bob, &charlie, &debbie])
                    .await
            );

            // After merging we should erase all those pending messages
            assert_eq!(alice.transaction.count_entities().await.pending_messages, 0);
        })
        .await
    }

    /// Replicating [WPB-15810]
    ///
    /// [WPB-15810]: https://wearezeta.atlassian.net/browse/WPB-15810
    #[apply(all_cred_cipher)]
    async fn wpb_15810(mut case: TestContext) {
        if case.is_pure_ciphertext() {
            // The use case tested here requires inspecting your own commit.
            // Openmls does not support this currently when protocol messages are encrypted.
            return;
        }

        let [external_0, new_member, member_27, observer, member_114, member_115] = case.sessions().await;
        Box::pin(async move {
            // set up external_0 as the backend / delivery service
            // scenario start: everyone except "new_member" is in the conversation
            let conversation = case
                .create_conversation_with_external_sender(
                    &external_0,
                    [&observer, &member_114, &member_115, &member_27],
                )
                .await;

            // Everyone should agree on the overall state here, to wit: the group consists of everyone
            // except "new_member", and "external_0", and no messages have been sent.
            // At this point only the observer is going to receive messages, because that shouldn't impact group state.

            // external 0 sends a proposal to remove 114
            let proposal_guard = conversation.external_remove_proposal(&external_0, &member_114).await;
            let proposal_remove_114_1 = proposal_guard.message();
            let conversation = proposal_guard.finish();

            // now bump the epoch in external_0: the new member has joined
            let (commit_guard, mut pending_conversation) = conversation.external_join_unmerged(&new_member).await;

            let new_member_join_commit = commit_guard.message();

            pending_conversation.merge().await.unwrap();
            let conversation = commit_guard.process_member_changes().await.finish();

            // also create the same proposal with the epoch increased by 1
            let proposal_guard = conversation
                .acting_as(&new_member)
                .await
                .external_remove_proposal(&external_0, &member_114)
                .await;
            let proposal_remove_114_2 = proposal_guard.message();
            let conversation = proposal_guard.finish();

            // now our observer receives these messages out of order
            println!("observer executing first proposal");
            conversation
                .guard()
                .await
                .decrypt_message(&proposal_remove_114_1.to_bytes().unwrap())
                .await
                .unwrap();
            println!("observer executing second proposal");
            let result = conversation
                .guard()
                .await
                .decrypt_message(&proposal_remove_114_2.to_bytes().unwrap())
                .await;
            assert!(matches!(
                result.unwrap_err(),
                Error::BufferedFutureMessage { message_epoch: 2 }
            ));
            println!("executing commit adding new user");
            conversation
                .guard()
                .await
                .decrypt_message(&new_member_join_commit.to_bytes().unwrap())
                .await
                .unwrap();

            // now the new member receives the messages in order
            println!("new_member executing first proposal");
            assert!(matches!(
                conversation
                    .guard_of(&new_member)
                    .await
                    .decrypt_message(&proposal_remove_114_1.to_bytes().unwrap())
                    .await
                    .unwrap_err(),
                crate::mls::conversation::Error::StaleProposal,
            ));
            println!("new_member executing second proposal");
            conversation
                .guard_of(&new_member)
                .await
                .decrypt_message(&proposal_remove_114_2.to_bytes().unwrap())
                .await
                .unwrap();

            // now let's switch to the perspective of member 27
            // they have observed exactly one of the "remove 114" proposals,
            // plus a "remove 115" proposal. We can assume that they observe the 2nd
            // "remove 114" proposal because they advanced the epoch correctly when
            // the new member was added.
            let proposal_guard = conversation.external_remove_proposal(&external_0, &member_115).await;
            let proposal_remove_115 = proposal_guard.message();
            let conversation = proposal_guard.finish();

            conversation
                .guard_of(&member_27)
                .await
                .decrypt_message(&proposal_remove_114_1.to_bytes().unwrap())
                .await
                .unwrap();
            let result = conversation
                .guard_of(&member_27)
                .await
                .decrypt_message(&proposal_remove_114_2.to_bytes().unwrap())
                .await;
            assert!(matches!(
                result.unwrap_err(),
                Error::BufferedFutureMessage { message_epoch: 2 }
            ));
            conversation
                .guard_of(&member_27)
                .await
                .decrypt_message(&new_member_join_commit.to_bytes().unwrap())
                .await
                .unwrap();
            conversation
                .guard_of(&member_27)
                .await
                .decrypt_message(&proposal_remove_115.to_bytes().unwrap())
                .await
                .unwrap();

            // In this case, note that observer receives the proposal before the commit.
            // This is the straightforward ordering and easy to deal with.
            conversation
                .guard()
                .await
                .decrypt_message(&proposal_remove_115.to_bytes().unwrap())
                .await
                .unwrap();

            let commit_guard = conversation
                .acting_as(&member_27)
                .await
                .commit_pending_proposals()
                .await
                .notify_member(&observer)
                .await;

            // In this case, new_member receives the commit before the proposal. This means that
            // the commit has to be buffered until the proposal it references is received.
            let (commit_guard, result) = commit_guard.notify_member_fallible(&new_member).await;
            assert!(matches!(result.unwrap_err(), Error::BufferedCommit));
            let conversation = commit_guard.process_member_changes().await.finish();
            conversation
                .guard_of(&new_member)
                .await
                .decrypt_message(&proposal_remove_115.to_bytes().unwrap())
                .await
                .unwrap();

            assert!(
                conversation
                    .is_functional_and_contains([&observer, &new_member, &member_27])
                    .await
            )
        })
        .await
    }
}
