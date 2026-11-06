//! Handle messages which can't be processed yet by storing them in an inbox until proper handling is possible.

use core_crypto_keystore::{
    entities::{InboxMessage, WaitingFor},
    traits::{DeletableBySearchKey, EntityDatabaseMutation as _},
};
use log::{info, warn};

use super::{Error, IncomingMessage, RecursionPolicy, Result};
use crate::{
    BufferedDecryptedMessage, DecryptionOutcome, DeferralReason, KeystoreError, RecursiveError,
    error::infrastructure::Infrastructural as _,
    mls::conversation::{ConversationMut, mutable::decrypt::ParsedMessage},
};

impl ConversationMut {
    /// Send an incoming message to the inbox for processing later, once its deferral reason is satisfied.
    pub(super) fn send_to_inbox(&self, message: &IncomingMessage, reason: &DeferralReason) -> Result<()> {
        let context_inner = self.tx_context.inner().map_err(RecursiveError::context(
            "getting transaction inner to get arrival sequence",
        ))?;
        let tx = context_inner.transaction();
        self.send_to_inbox_with_arrival_sequence(message, reason, tx.inbox_message_next_arrival_sequence())
    }

    /// Send an incoming message to the inbox for processing later, once its deferral reason is satisfied.
    ///
    /// Here the arrival sequence is manually specified; this is mainly intended for messages which
    /// were re-deferred after an initial deferral failed to process them.
    fn send_to_inbox_with_arrival_sequence(
        &self,
        message: &IncomingMessage,
        reason: &DeferralReason,
        arrival_sequence: u64,
    ) -> Result<()> {
        let waiting_for = match reason {
            DeferralReason::FutureEpoch { .. } => WaitingFor::Epoch,
            DeferralReason::MissingProposal => WaitingFor::Proposal,
        };
        let epoch = message.parsed.epoch()?;

        // sanity check
        if let DeferralReason::FutureEpoch { epoch: reason_epoch } = reason {
            debug_assert_eq!(
                epoch, *reason_epoch,
                "when waiting for an epoch, the deferral epoch must match"
            );
        }

        info!(group_id = self.id.clone(), epoch, reason:?; "saving message to inbox");

        let context_inner = self.tx_context.inner().map_err(RecursiveError::context(
            "getting transaction inner to save message to inbox",
        ))?;
        let tx = context_inner.transaction();

        let inbox_message = InboxMessage {
            content_type: message.parsed.content_type()?,
            conversation_id: self.id().into(),
            message: message.bytes.to_owned(),
            epoch,
            waiting_for,
            arrival_sequence,
        };
        inbox_message
            .save(tx)
            .map_err(KeystoreError::wrap("saving inbox message"))?;
        Ok(())
    }

    /// Clear pending messages for this conversation.
    pub(crate) fn clear_pending_messages(&self) -> Result<()> {
        let tx = self
            .tx_context
            .inner()
            .map_err(RecursiveError::context("getting tx context to clear pending messages"))?;
        InboxMessage::delete_all_matching(tx.transaction(), self.id().keystore())
            .map_err(KeystoreError::wrap("clearing pending messages"))?;
        Ok(())
    }

    /// Take everything waiting for the given reason / epoch, and replay it in order.
    ///
    /// - Replays each item matching the parameters
    /// - Re-buffers any which defers again, with the new reason
    /// - Any item which is stale or fails to parse is dropped with a warning log
    #[cfg_attr(target_os = "unknown", async_recursion::async_recursion(?Send))]
    #[cfg_attr(not(target_os = "unknown"), async_recursion::async_recursion)]
    pub(crate) async fn replay_from_inbox(
        &mut self,
        waiting_for: WaitingFor,
        epoch: Option<u64>,
    ) -> Result<Vec<BufferedDecryptedMessage>> {
        let tx_context_inner = self.tx_context.inner().map_err(RecursiveError::context(
            "getting tx context to restore pending messages",
        ))?;
        let tx = tx_context_inner.transaction();

        // returns messages in order of content type, then arrival sequence
        let pending_messages = InboxMessage::take(tx, self.id().keystore(), waiting_for, epoch)
            .map_err(KeystoreError::wrap("taking inbox messages from the db"))?;

        if !pending_messages.is_empty() {
            info!(group_id = self.id().to_owned(), waiting_for:?, epoch; "Attempting to restore {} messages from the inbox", pending_messages.len());
        }

        let mut decrypted_messages = Vec::with_capacity(pending_messages.len());
        for inbox_message in pending_messages {
            let incoming_message = match IncomingMessage::parse(&inbox_message.message) {
                Ok(incoming) => incoming,
                Err(err) => {
                    warn!(err:err, group_id = self.id().to_owned(), epoch; "failed to parse buffered message while taking from inbox; dropping");
                    continue;
                }
            };

            let maybe_decrypted = tx_context_inner
                .with_savepoint(
                    "replay_from_inbox",
                    async || match incoming_message.parsed.clone() {
                        ParsedMessage::Mls(mls_message) => {
                            self.decrypt_mls_message(mls_message, RecursionPolicy::None).await
                        }
                        ParsedMessage::Tnt(tnt_message) => self.decrypt_tnt_message(tnt_message).await,
                    },
                    Error::savepoint,
                )
                .await;

            let decrypted = match maybe_decrypted {
                Ok(DecryptionOutcome::Decrypted(decrypted)) => decrypted,
                Ok(DecryptionOutcome::Deferred(reason)) => {
                    // we've taken the message out, but it wasn't ready, so let's just put it back
                    self.send_to_inbox_with_arrival_sequence(
                        &incoming_message,
                        &reason,
                        inbox_message.arrival_sequence,
                    )?;
                    continue;
                }
                Err(err) => {
                    if err.is_infrastructure() {
                        // propagate infrastructure errors so the whole transaction rolls back and we can try again
                        // later
                        return Err(err);
                    } else {
                        warn!(error:% = err; "failed to decrypt buffered message");
                        continue;
                    }
                }
            };
            decrypted_messages.push(decrypted.into());
        }

        Ok(decrypted_messages)
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        DecryptedMessage,
        mls::conversation::{Error, config::OUT_OF_ORDER_TOLERANCE},
        test_utils::*,
    };

    #[apply(all_cred_cipher)]
    async fn can_operate_with_pending_commit_wpb_17356(case: TestContext) {
        let [alice] = case.sessions().await;
        let conversation = case.create_conversation([&alice]).await;
        // create a pending commit
        let conversation = conversation.update_unmerged().await.finish();
        let mut conversation = conversation.guard().await;
        // This should work, even though there is a pending commit!
        assert!(conversation.group().await.pending_commit().is_some());
        conversation.update_key_material().await.unwrap();
        assert!(conversation.group().await.pending_commit().is_none());
    }

    #[apply(all_cred_cipher)]
    async fn should_buffer_and_reapply_messages_after_commit_merged_for_sender(case: TestContext) {
        let [alice, bob, charlie, debbie] = case.sessions().await;
        Box::pin(async move {
            let conversation = case.create_conversation([&alice, &bob, &debbie]).await;

            // Bob creates a commit but won't merge it immediately (e.g, because his app crashes before he receives the
            // success response from the ds)
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

            let proposal_guard = conversation.remove_proposal(&debbie).await;
            let remove_proposal = proposal_guard.message();
            let conversation = proposal_guard.finish();

            // This commit will contain the invitation of charlie and debbie's removal
            let commit_guard = conversation.invite([&charlie]).await;
            let commit = commit_guard.message();
            // This will make charlie process welcome message
            let conversation = commit_guard.process_member_changes().await.finish();

            // And now Bob will have to decrypt those messages while he hasn't yet merged its commit
            // To add more fun, he will buffer the messages in exactly the wrong order (to make
            // sure he reapplies them in the right order afterwards)
            let messages = [commit, remove_proposal]
                .into_iter()
                .map(|m| m.to_bytes().unwrap())
                .chain(std::iter::once(app_msg));
            for m in messages {
                let decrypt = conversation.guard_of(&bob).await.decrypt_message(m).await;
                assert!(matches!(decrypt.unwrap_err(), Error::BufferedFutureMessage { .. }));
            }

            // Bob should have buffered the messages
            assert_eq!(bob.transaction.count_entities().await.pending_messages, 3);

            let observer = TestEpochObserver::new();
            bob.session()
                .await
                .register_epoch_observer(observer.clone())
                .await
                .unwrap();

            // Finally, Bob receives the green light from the DS and he can merge the external commit
            let restored_messages = conversation
                .guard_of(&bob)
                .await
                .decrypt_message(unmerged_commit.to_bytes().unwrap())
                .await
                .unwrap()
                .into_commit()
                .unwrap()
                .buffered_messages
                .expect("Alice's messages should have been restored at this point");

            for (idx, buffered_message) in restored_messages.into_iter().enumerate() {
                let text = DecryptedMessage::from(buffered_message).into_application_message();
                if idx == 0 {
                    // this is the application message
                    assert_eq!(text.unwrap().plaintext, b"Hello Bob !");
                } else {
                    assert!(text.is_err());
                }
            }

            assert_eq!(conversation.member_count().await, 3);
            assert!(conversation.is_functional_and_contains([&alice, &bob, &charlie]).await);

            // After merging we should erase all those pending messages
            assert_eq!(bob.transaction.count_entities().await.pending_messages, 0);

            bob.transaction.finish().await.unwrap();

            let observed_epochs = observer
                .observed_epochs()
                .await
                .into_iter()
                .map(|(_conversation_id, epoch)| epoch)
                .collect::<Vec<_>>();
            dbg!(&observed_epochs);
            assert_eq!(observed_epochs.len(), 1, "there was 1 commit changing the epoch");
        })
        .await
    }

    #[apply(all_cred_cipher)]
    async fn should_buffer_and_reapply_messages_after_commit_merged_for_receivers(case: TestContext) {
        let [alice, bob, charlie, debbie] = case.sessions().await;
        Box::pin(async move {
            let conversation = case.create_conversation([&alice, &bob, &charlie]).await;

            // Bob creates a commit...
            let commit_guard = conversation.acting_as(&bob).await.update().await;
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
            let proposal_guard = conversation.acting_as(&bob).await.remove_proposal(&charlie).await;
            let proposal = proposal_guard.message();
            let commit_guard = proposal_guard.finish().acting_as(&bob).await.invite([&debbie]).await;
            let commit = commit_guard.message();
            let conversation = commit_guard.process_member_changes().await.finish();

            // And now Alice will have to decrypt those messages while he hasn't yet merged the commit
            // To add more fun, he will buffer the messages in exactly the wrong order (to make
            // sure he reapplies them in the right order afterwards)
            let messages = vec![commit, proposal].into_iter().map(|m| m.to_bytes().unwrap());
            for m in messages {
                let decrypt = conversation.guard_of(&alice).await.decrypt_message(m).await;
                assert!(matches!(decrypt.unwrap_err(), Error::BufferedFutureMessage { .. }));
            }
            let decrypt = conversation.guard().await.decrypt_message(app_msg).await;
            assert!(matches!(decrypt.unwrap_err(), Error::BufferedFutureMessage { .. }));

            // Alice should have buffered the messages
            assert_eq!(alice.transaction.count_entities().await.pending_messages, 3);

            let observer = TestEpochObserver::new();
            alice
                .session()
                .await
                .register_epoch_observer(observer.clone())
                .await
                .unwrap();

            // Finally, Alice receives the original commit for this epoch
            let original_commit = ext_commit.to_bytes().unwrap();
            let restored_messages = conversation
                .guard()
                .await
                .decrypt_message(original_commit)
                .await
                .unwrap()
                .into_commit()
                .unwrap()
                .buffered_messages
                .expect("Alice's messages should have been restored at this point");
            for (idx, buffered_message) in restored_messages.into_iter().enumerate() {
                let text = DecryptedMessage::from(buffered_message).into_application_message();
                if idx == 0 {
                    assert_eq!(text.unwrap().plaintext, b"Hello Alice !");
                } else {
                    assert!(text.is_err());
                }
            }

            assert_eq!(conversation.member_count().await, 3);
            assert!(conversation.is_functional_and_contains([&alice, &bob, &debbie]).await);

            // After merging we should erase all those pending messages
            assert_eq!(alice.transaction.count_entities().await.pending_messages, 0);

            alice.transaction.finish().await.unwrap();

            let observed_epochs = observer
                .observed_epochs()
                .await
                .into_iter()
                .map(|(_conversation_id, epoch)| epoch)
                .collect::<Vec<_>>();
            dbg!(&observed_epochs);
            assert_eq!(
                observed_epochs.len(),
                3,
                "there was 2 buffered commits changing the epoch plus the outer commit changing the epoch"
            );
        })
        .await
    }

    /// A buffered future message must not block us from processing our own removal.
    ///
    /// This is ordinary out-of-order delivery, the very thing the buffering machinery exists for:
    /// the DS hands us an epoch `n + 1` application message before it hands us the epoch `n + 1`
    /// commit which removed us. Once that commit arrives, the conversation must be wiped, and the
    /// buffered message must go with it. If instead the buffered message is replayed against the
    /// new epoch, decryption fails identically on every retry, in every subsequent transaction, so
    /// the client can never process its own removal and the conversation is stuck forever.
    #[apply(all_cred_cipher)]
    async fn buffered_message_must_not_block_own_removal(case: TestContext) {
        let [mut alice, bob, charlie] = case.sessions().await;
        let conversation = case.create_conversation([&alice, &bob, &charlie]).await;
        let conversation_id = conversation.id().clone();

        // Bob removes Alice. Charlie hears about it; Alice does not, so she stays at epoch 1.
        let commit_guard = conversation.acting_as(&bob).await.remove(&alice).await;
        let removal_commit = commit_guard.message().to_bytes().unwrap();
        let conversation = commit_guard
            .notify_member(&charlie)
            .await
            .process_member_changes()
            .await
            .finish();

        // Bob then speaks in the new epoch.
        let app_msg = conversation
            .guard_of(&bob)
            .await
            .encrypt_message(b"Hello from epoch 2!")
            .await
            .unwrap();

        // Alice is still at epoch 1, so she buffers the message.
        let decrypt = conversation.guard_of(&alice).await.decrypt_message(app_msg).await;
        assert!(matches!(
            decrypt.unwrap_err(),
            Error::BufferedFutureMessage { message_epoch: 2 }
        ));
        assert_eq!(
            alice.transaction.count_entities().await.pending_messages,
            1,
            "the message Alice could not decrypt must have been buffered"
        );

        // Commit Alice's transaction, so the buffered message is durable, as it would be
        // between two real client calls.
        drop(conversation);
        alice.commit_transaction().await;

        // Only now does Alice receive the commit which removed her.
        let decrypted = alice
            .transaction
            .conversation(&conversation_id)
            .await
            .unwrap()
            .decrypt_message(&removal_commit)
            .await
            .expect("Alice must be able to process her own removal")
            .into_commit()
            .unwrap();
        assert!(
            !decrypted.is_active,
            "the commit removed Alice, so she is no longer an active member"
        );

        alice.commit_transaction().await;

        let counts = alice.transaction.count_entities().await;
        assert_eq!(
            counts.group, 0,
            "processing her own removal must have wiped the conversation"
        );
        assert_eq!(
            counts.pending_messages, 0,
            "the buffered message belongs to a conversation which no longer exists"
        );
    }

    /// A buffered commit which removes us must still wipe the conversation.
    ///
    /// The eviction can arrive out of order: the DS hands us the commit which removes us before
    /// the earlier commit we need in order to process it, so the removal is buffered and only
    /// replayed once that earlier commit merges. The replay is what actually evicts us, so the
    /// earlier commit's decryption result is the only place the caller can learn about it, and it
    /// therefore has to report us as inactive. Otherwise nothing wipes the conversation: the
    /// keystore keeps a group we've been evicted from, every subsequent operation on it fails
    /// inside openmls with `UseAfterEviction`, and the client is never told it was removed.
    #[apply(all_cred_cipher)]
    async fn buffered_commit_removing_self_must_wipe_conversation(case: TestContext) {
        let [mut alice, bob, charlie] = case.sessions().await;
        let conversation = case.create_conversation([&alice, &bob, &charlie]).await;
        let conversation_id = conversation.id().clone();

        // Bob commits at epoch 1, advancing the group to epoch 2. Charlie hears about it;
        // Alice does not, so she stays at epoch 1.
        let commit_guard = conversation.acting_as(&bob).await.update().await;
        let first_commit = commit_guard.message().to_bytes().unwrap();
        let conversation = commit_guard.notify_member(&charlie).await.finish();

        // Bob then removes Alice, at epoch 2.
        let commit_guard = conversation.acting_as(&bob).await.remove(&alice).await;
        let removal_commit = commit_guard.message().to_bytes().unwrap();
        let conversation = commit_guard
            .notify_member(&charlie)
            .await
            .process_member_changes()
            .await
            .finish();

        // The DS delivers the removal to Alice first. She's still at epoch 1, so she buffers it.
        let decrypt = conversation
            .guard_of(&alice)
            .await
            .decrypt_message(&removal_commit)
            .await;
        assert!(matches!(
            decrypt.unwrap_err(),
            Error::BufferedFutureMessage { message_epoch: 2 }
        ));
        assert_eq!(
            alice.transaction.count_entities().await.pending_messages,
            1,
            "the commit Alice could not yet apply must have been buffered"
        );

        // Commit Alice's transaction, so the buffered commit is durable, as it would be
        // between two real client calls.
        drop(conversation);
        alice.commit_transaction().await;

        // Only now does Alice receive the commit which unblocks the buffered removal.
        let decrypted = alice
            .transaction
            .conversation(&conversation_id)
            .await
            .unwrap()
            .decrypt_message(&first_commit)
            .await
            .expect("the earlier commit must apply")
            .into_commit()
            .unwrap();
        assert!(
            !decrypted.is_active,
            "replaying the buffered commit removed Alice, so she is no longer an active member"
        );

        alice.commit_transaction().await;

        let counts = alice.transaction.count_entities().await;
        assert_eq!(
            counts.group, 0,
            "processing her own removal must have wiped the conversation"
        );
        assert_eq!(
            counts.pending_messages, 0,
            "the buffered commit belongs to a conversation which no longer exists"
        );
    }

    /// Buffered application messages are restored as far as the out-of-order tolerance allows.
    ///
    /// The DS doesn't guarantee delivery order, so application messages for a new epoch can be
    /// buffered in any order relative to each other. We replay them in the order they were
    /// buffered, and we can't do better: a message's generation lives in its encrypted sender
    /// data, so we can't sort the buffer by it without decrypting first.
    ///
    /// That costs us messages. Decrypting the newest generation first advances the ratchet past
    /// it and immediately discards every past secret outside the tolerance window, so only
    /// `OUT_OF_ORDER_TOLERANCE` of the buffered messages are still decryptable by the time we
    /// reach them. We accept that loss, but it has to stay contained: the commit itself must
    /// still merge and report success, and the buffer must still be cleared, so that an
    /// undecryptable message can neither fail the commit nor poison every future restore.
    #[apply(all_cred_cipher)]
    async fn buffered_messages_are_restored_within_out_of_order_tolerance(case: TestContext) {
        const MESSAGE_COUNT: u8 = 4;

        let [alice, bob] = case.sessions().await;
        let conversation = case.create_conversation([&alice, &bob]).await;

        // Bob commits and merges immediately into his own state; Alice does not receive it yet.
        let commit_guard = conversation.acting_as(&bob).await.update().await;
        let commit = commit_guard.message();
        let conversation = commit_guard.process_member_changes().await.finish();

        // Bob sends more application messages in the new epoch than the tolerance window covers,
        // at generations 0..MESSAGE_COUNT.
        let mut app_messages = Vec::with_capacity(MESSAGE_COUNT.into());
        for i in 0..MESSAGE_COUNT {
            let msg = conversation.guard_of(&bob).await.encrypt_message([i]).await.unwrap();
            app_messages.push(msg);
        }

        // The DS hands these to Alice newest first, oldest last. Alice is still on the old epoch,
        // so each one gets buffered individually, in that same order.
        for msg in app_messages.iter().rev() {
            let decrypt = conversation.guard_of(&alice).await.decrypt_message(msg).await;
            assert!(matches!(decrypt.unwrap_err(), Error::BufferedFutureMessage { .. }));
        }
        assert_eq!(
            alice.transaction.count_entities().await.pending_messages,
            u32::from(MESSAGE_COUNT)
        );

        // Alice now receives the commit. It must merge, and whichever buffered messages are still
        // decryptable must come back with it.
        let restored = conversation
            .guard_of(&alice)
            .await
            .decrypt_message(commit.to_bytes().unwrap())
            .await
            .expect("the commit must merge even though some buffered messages can't be decrypted")
            .into_commit()
            .unwrap()
            .buffered_messages
            .expect("the buffered messages within the tolerance window should have been restored");

        let restored_plaintexts = restored
            .into_iter()
            .map(|m| DecryptedMessage::from(m).into_application_message().unwrap().plaintext[0])
            .collect::<Vec<_>>();
        let expected_plaintexts = ((MESSAGE_COUNT - OUT_OF_ORDER_TOLERANCE as u8)..MESSAGE_COUNT)
            .rev()
            .collect::<Vec<_>>();
        assert_eq!(
            restored_plaintexts, expected_plaintexts,
            "only the newest OUT_OF_ORDER_TOLERANCE messages are still decryptable in replay order"
        );

        assert_eq!(
            conversation.guard_of(&alice).await.group().await.epoch().as_u64(),
            conversation.guard_of(&bob).await.group().await.epoch().as_u64(),
            "the commit must have merged into Alice's group"
        );
        assert_eq!(
            alice.transaction.count_entities().await.pending_messages,
            0,
            "the buffer must be cleared even though some of its messages could not be decrypted"
        );
    }

    /// Replicating [WPB-15810]
    ///
    /// [WPB-15810]: https://wearezeta.atlassian.net/browse/WPB-15810
    /// Overflows with default stack size in debug mode for ML-DSA-87, passes with increased stack size.
    #[apply(all_cred_cipher)]
    async fn wpb_15810(mut case: TestContext) {
        case.sessions_in_memory = true;
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
