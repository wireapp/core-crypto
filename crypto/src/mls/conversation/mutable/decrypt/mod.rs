//! MLS defines 3 kind of messages: Proposal, Commits and Application messages. Since they can (should)
//! be all encrypted we need to first decrypt them before deciding what to do with them.
//!
//! This table summarizes when an MLS group can decrypt any message:
//!
//! | can decrypt ?     | 0 pend. Commit | 1 pend. Commit |
//! |-------------------|----------------|----------------|
//! | 0 pend. Proposal  | ✅              | ✅              |
//! | 1+ pend. Proposal | ✅              | ✅              |

mod buffer_commit;
mod handle;
mod inbox;
mod incoming_message;
mod outputs;
mod process_message;

use std::{borrow::Cow, collections::VecDeque};

use core_crypto_keystore::entities::{InboxMessage, WaitingFor};
use log::warn;
use openmls::{
    framing::MlsMessageIn,
    group::MlsGroup,
    prelude::{CredentialType, LeafNodeIndex, Member, ProcessedMessageContent, StagedCommit},
};
use openmls_traits::OpenMlsCryptoProvider as _;

pub(in crate::mls::conversation) use self::incoming_message::{IncomingMessage, ParsedMessage};
pub use self::outputs::{
    BufferedCommit, BufferedDecryptedMessage, Commit, DecryptedBytes, DecryptedMessage, DecryptionOutcome,
    DeferralReason, Proposal,
};
use self::{
    outputs::Effect,
    process_message::{ProcessedMessage, process_message},
};
use super::{ConversationMut, Result};
use crate::{
    E2eiConversationState, RecursiveError, Session, TlsCodecError,
    error::infrastructure::Infrastructural as _,
    mls::{conversation::Error, credential::ext::CredentialExt as _},
};

impl ConversationMut {
    /// Decrypt and process a MLS or TNT message.
    ///
    /// Effect on local state depends on what the message turns out to be:
    ///
    /// - a commit from another member supersedes any local pending commit, and consumes all pending proposals;
    /// - our own commit, delivered back to us, is merged rather than discarded;
    /// - proposals and application messages leave local pending state untouched.
    ///
    /// The message bytes must be TLS-serialized.
    ///
    /// Returns a vector. The first item in this vector is always the message this function was called with;
    /// subsequent items are buffered messages which have been unblocked by that first message. If the initial
    /// message was deferred, this vector will be empty.
    ///
    /// Errors occurred when decrypting the message with which this function was called propagate as normal.
    /// Errors occurred when decrypting buffered messages unblocked by the initial message are propagated in
    /// case they are infrastructure errors. If they are not, then they are logged but not propagated, and the
    /// related message is dropped.
    pub async fn decrypt_message(&mut self, bytes: impl Into<Cow<'_, [u8]>>) -> Result<Vec<DecryptedMessage>> {
        let id = self.id.clone();
        let log_and_skip_unparseable_buffered_messages = move |maybe_message: Result<
            (InboxMessage, IncomingMessage),
            TlsCodecError,
        >| {
            match maybe_message {
                Ok((inbox, incoming)) => Some((incoming, inbox.message.into())),
                Err(err) => {
                    warn!(err:err, group_id = id.clone(); "failed to parse buffered message while taking from inbox; dropping");
                    None
                }
            }
        };

        let bytes = bytes.into();
        let incoming_message = IncomingMessage::parse(&bytes)?;
        let mut queue = VecDeque::from([(incoming_message, bytes)]);
        let mut decrypted_messages = Vec::new();

        let tx_context_inner = self
            .tx_context
            .inner()
            .map_err(RecursiveError::context("getting tx context inner to decrypt a message"))?;
        while let Some((message, bytes)) = queue.pop_front() {
            // we don't swallow these errors even when processing buffered messages:
            // for a message to be buffered, it must previously have been parseable, so these
            // should only ever propagate on the first item in the queue.
            let content_type = message.parsed.content_type()?;
            let epoch = message.parsed.epoch()?;
            let arrival_sequence = message.arrival_sequence;

            let outcome_result = tx_context_inner
                .with_savepoint(
                    "decrypt_message",
                    async || match message.parsed {
                        ParsedMessage::Mls(mls_message_in) => self.decrypt_mls_message(mls_message_in).await,
                        ParsedMessage::Tnt(tnt_message) => self.decrypt_tnt_message(tnt_message).await,
                    },
                    Error::savepoint,
                )
                .await;

            let outcome = match outcome_result {
                Ok(outcome) => outcome,
                Err(err) if arrival_sequence.is_none() || err.is_infrastructure() => {
                    // If the arrival sequence is none, this was the original message the caller passed in;
                    // it's appropriate to return a decryption error in that case.
                    // If the arrival sequence is not None, then this message had been buffered;
                    // in that case, we'd report infrastructure errors, but swallow non-infrastructure errors.
                    return Err(err);
                }
                Err(err) => {
                    // non-infrastructure errors just drop the offending message
                    warn!(err:err, group_id = self.id.clone(); "failed to decrypt a message; dropping");
                    continue;
                }
            };

            let effect = match &outcome {
                DecryptionOutcome::Decrypted(DecryptedMessage::Commit(commit)) => Effect::EpochAdvanced {
                    new_epoch: self.epoch().await,
                    is_active: commit.is_active,
                },
                DecryptionOutcome::Decrypted(DecryptedMessage::Proposal(_)) => Effect::ProposalStored,
                _ => Effect::None,
            };

            if let DecryptionOutcome::Deferred(reason) = &outcome {
                self.send_to_inbox(content_type, epoch, arrival_sequence, bytes.into_owned(), reason)?;
            }

            // This will change in WPB-29261 to something like
            //   if !(item.arrival_sequence.is_some() && outcome.is_deferred())
            // but for now because we don't actually return outcomes,
            // we need a narrower filter.
            if let DecryptionOutcome::Decrypted(decrypted) = outcome {
                decrypted_messages.push(decrypted);
            }

            match effect {
                Effect::None => {}
                Effect::ProposalStored => {
                    // if we stored a proposal, then it's time to unearth any commits and see if any of them can apply
                    // now
                    queue.extend(
                        self.inbox_take(WaitingFor::Proposal, self.epoch().await.into())?
                            .filter_map(&log_and_skip_unparseable_buffered_messages),
                    );
                }
                Effect::EpochAdvanced { new_epoch, is_active } => {
                    // notify the epoch change in every case
                    self.tx_context
                        .queue_epoch_changed(self.id.clone(), new_epoch)
                        .await
                        .map_err(RecursiveError::context("queueing epoch change notification"))?;

                    // if we're no longer in the group, cleanup is simpler
                    if !is_active {
                        self.wipe().await?;
                        break;
                    }

                    // we're now ready to process any messages which were waiting for this epoch
                    queue.extend(
                        self.inbox_take(WaitingFor::Epoch, new_epoch.into())?
                            .filter_map(&log_and_skip_unparseable_buffered_messages),
                    );
                }
            }
        }

        Ok(decrypted_messages)
    }

    /// Decrypt a single MLS message, reporting but not taking action on its outcome.
    async fn decrypt_mls_message(&mut self, message: MlsMessageIn) -> Result<DecryptionOutcome> {
        let message = match process_message(self, message).await? {
            // processing succeeded
            ProcessedMessage::Content(message) => message,

            // Handles the case where we receive our own commits.
            ProcessedMessage::OwnCommit(confirmation_tag) => {
                let decrypted_message = self.handle_own_commit(&confirmation_tag).await?;
                return Ok(decrypted_message.into());
            }
            ProcessedMessage::Deferred(reason) => return Ok(reason.into()),
        };

        let credential = message.credential();
        let epoch = message.epoch();

        let pki_env = self.crypto_provider().await?.authentication_service().pki_env().await;
        let identity = credential
            .extract_identity(self.cipher_suite().signature_algorithm(), pki_env.as_deref())
            .await
            .map_err(RecursiveError::context("extracting identity"))?;

        // We only need this in the ProcessedMessageContent::ApplicationMessage match arm below, however, at that point
        // we cannot borrow from `message` anymore, because it is moved by `message.into_content()`.
        let sender_client_id_result = credential
            .credential
            .identity()
            .try_into()
            .map_err(RecursiveError::context("client id from credential"));

        let decrypted = match message.into_content() {
            ProcessedMessageContent::ApplicationMessage(app_msg) => {
                handle::application(self, app_msg, epoch, identity, sender_client_id_result)?
            }
            ProcessedMessageContent::ProposalMessage(proposal) => handle::proposal(self, *proposal, identity).await?,
            ProcessedMessageContent::StagedCommitMessage(staged_commit) => {
                handle::staged_commit(self, *staged_commit, identity).await?
            }
            ProcessedMessageContent::ExternalJoinProposalMessage(proposal) => {
                handle::external_join_proposal(self, *proposal, identity).await?
            }
        };

        Ok(decrypted.into())
    }

    fn members_at_indices(indices: Vec<LeafNodeIndex>, group: &MlsGroup) -> Vec<Member> {
        group
            .members()
            .filter_map(|member| indices.contains(&member.index).then_some(member))
            .collect::<Vec<_>>()
    }

    async fn validate_commit(&self, commit: &StagedCommit) -> Result<()> {
        let backend = self.crypto_provider().await?;
        if backend.is_pki_env_setup().await {
            let credentials: Vec<_> = commit
                .add_proposals()
                .filter_map(|add_proposal| {
                    let credential = add_proposal.add_proposal().key_package().leaf_node().credential();

                    matches!(credential.credential_type(), CredentialType::X509).then(|| credential.clone())
                })
                .collect();
            let state = Session::compute_conversation_state(
                credentials.iter(),
                crate::CredentialType::X509,
                backend.authentication_service(),
            )
            .await;
            if state != E2eiConversationState::Verified {
                // FIXME: Uncomment when PKI env can be seeded - the computation is still done to assess performance and
                // impact of the validations. Tracking issue: WPB-9665
                // return Err(Error::InvalidCertificateChain);
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        mls::conversation::{
            config::{MAX_PAST_EPOCHS, OUT_OF_ORDER_TOLERANCE},
            error::Error,
        },
        test_utils::*,
    };

    mod is_active {
        use super::*;

        #[apply(all_cred_cipher)]
        pub async fn decrypting_a_regular_commit_should_leave_conversation_active(case: TestContext) {
            let [alice, bob] = case.sessions().await;
            Box::pin(async move {
                let conversation = case.create_conversation([&alice, &bob]).await;

                let (_, decrypted) = conversation
                    .acting_as(&bob)
                    .await
                    .update()
                    .await
                    .notify_member_fallible(&alice)
                    .await;
                let decrypted = decrypted.unwrap();
                assert!(decrypted.as_commit().is_some_and(|commit| commit.is_active))
            })
            .await
        }

        #[apply(all_cred_cipher)]
        pub async fn decrypting_a_commit_removing_self_should_set_conversation_inactive(case: TestContext) {
            let [alice, bob] = case.sessions().await;
            Box::pin(async move {
                let conversation = case.create_conversation([&alice, &bob]).await;

                let (_, decrypted) = conversation
                    .acting_as(&bob)
                    .await
                    .remove(&alice)
                    .await
                    .notify_member_fallible(&alice)
                    .await;
                let decrypted = decrypted.unwrap();
                assert!(decrypted.as_commit().is_some_and(|commit| !commit.is_active))
            })
            .await
        }
    }

    mod commit {
        use super::*;

        #[apply(all_cred_cipher)]
        pub async fn decrypting_a_commit_should_succeed(case: TestContext) {
            let [alice, bob] = case.sessions().await;
            Box::pin(async move {
                let conversation = case.create_conversation([&alice, &bob]).await;

                let bob_observer = TestEpochObserver::new();
                bob.session()
                    .await
                    .register_epoch_observer(bob_observer.clone())
                    .await
                    .unwrap();

                let epoch_before = conversation.guard().await.epoch().await;

                let (commit, decrypted) = conversation.update().await.notify_member_fallible(&bob).await;
                let decrypted = decrypted.unwrap();

                let epoch_after = commit.finish().guard_of(&bob).await.epoch().await;
                assert_eq!(epoch_after, epoch_before + 1);
                assert!(decrypted.as_commit().is_some());

                alice
                    .verify_sender_identity(&case, &alice.initial_credential, &decrypted)
                    .await;
                bob.transaction.finish().await.unwrap();
                assert!(bob_observer.has_changed().await);
            })
            .await
        }

        #[apply(all_cred_cipher)]
        async fn should_be_commit_variant(case: TestContext) {
            let [alice, bob] = case.sessions().await;
            Box::pin(async move {
                let conversation = case.create_conversation([&alice, &bob]).await;

                let (_commit, decrypted) = conversation.update().await.notify_member_fallible(&bob).await;

                assert!(decrypted.unwrap().as_commit().is_some());
            })
            .await
        }
    }

    mod proposal {
        use super::*;

        #[apply(all_cred_cipher)]
        async fn should_be_proposal_variant(case: TestContext) {
            let [alice, bob] = case.sessions().await;
            Box::pin(async move {
                let conversation = case.create_conversation([&alice, &bob]).await;

                let (_commit, decrypted) = conversation
                    .remove_proposal(&bob)
                    .await
                    .notify_member_fallible(&bob)
                    .await;

                assert!(decrypted.unwrap().as_proposal().is_some());
            })
            .await
        }
    }

    mod app_message {
        use super::*;

        #[apply(all_cred_cipher)]
        async fn can_decrypt_app_message(case: TestContext) {
            let [alice, bob] = case.sessions().await;
            Box::pin(async move {
                let conversation = case.create_conversation([&alice, &bob]).await;

                let alice_observer = TestEpochObserver::new();
                alice
                    .session()
                    .await
                    .register_epoch_observer(alice_observer.clone())
                    .await
                    .unwrap();
                let bob_observer = TestEpochObserver::new();
                bob.session()
                    .await
                    .register_epoch_observer(bob_observer.clone())
                    .await
                    .unwrap();

                let msg = b"Hello bob";
                let encrypted = conversation.guard().await.encrypt_message(msg).await.unwrap();
                assert_ne!(&msg[..], &encrypted[..]);
                let decrypted = conversation
                    .guard_of(&bob)
                    .await
                    .decrypt_message(encrypted)
                    .await
                    .unwrap();
                let dec_msg = &decrypted.as_application_message().unwrap().plaintext;
                assert_eq!(dec_msg, msg);
                assert!(!bob_observer.has_changed().await);
                alice
                    .verify_sender_identity(&case, &alice.initial_credential, &decrypted)
                    .await;

                let msg = b"Hello alice";
                let encrypted = conversation.guard_of(&bob).await.encrypt_message(msg).await.unwrap();
                assert_ne!(&msg[..], &encrypted[..]);
                let decrypted = conversation.guard().await.decrypt_message(encrypted).await.unwrap();
                let dec_msg = &decrypted.as_application_message().unwrap().plaintext;
                assert_eq!(dec_msg, &msg[..]);
                assert!(!alice_observer.has_changed().await);
                bob.verify_sender_identity(&case, &bob.initial_credential, &decrypted)
                    .await;
            })
            .await
        }

        #[apply(all_cred_cipher)]
        async fn cannot_decrypt_app_message_after_rejoining(case: TestContext) {
            let [alice, bob] = case.sessions().await;
            Box::pin(async move {
                let conversation = case.create_conversation([&alice, &bob]).await;

                // encrypt a message in epoch 1
                let msg = b"Hello bob";
                let encrypted = conversation.guard().await.encrypt_message(msg).await.unwrap();

                // Now Bob will rejoin the group and try to decrypt Alice's message
                // in epoch 2 which should fail
                let conversation = conversation.external_join_notify(&bob).await;

                // fails because of Forward Secrecy
                let decrypt = conversation.guard_of(&bob).await.decrypt_message(encrypted).await;
                assert!(matches!(decrypt.unwrap_err(), Error::DecryptionError));
            })
            .await
        }

        #[apply(all_cred_cipher)]
        async fn cannot_decrypt_app_message_from_future_epoch(case: TestContext) {
            let [alice, bob] = case.sessions().await;
            Box::pin(async move {
                let conversation = case.create_conversation([&alice, &bob]).await;

                // only Alice will change epoch without notifying Bob
                let commit_guard = conversation.update().await;
                let conversation = commit_guard.conversation();

                // Now in epoch 2 Alice will encrypt a message
                let msg = b"Hello bob";
                let encrypted = conversation.guard().await.encrypt_message(msg).await.unwrap();

                // which Bob cannot decrypt because of Post CompromiseSecurity
                let decrypt = conversation.guard_of(&bob).await.decrypt_message(encrypted).await;
                assert!(matches!(decrypt.unwrap_err(), Error::BufferedFutureMessage { .. }));

                let (_, decrypted_commit) = commit_guard.notify_member_fallible(&bob).await;
                let decrypted_commit = decrypted_commit.unwrap().into_commit().unwrap();
                let buffered_msg = decrypted_commit.buffered_messages.unwrap().remove(0);
                let decrypted_msg = crate::DecryptedMessage::from(buffered_msg);
                let decrypted_msg = &decrypted_msg.as_application_message().unwrap().plaintext;
                assert_eq!(&decrypted_msg, &msg);
            })
            .await
        }

        #[apply(all_cred_cipher)]
        async fn can_decrypt_app_message_in_reverse_order(case: TestContext) {
            let [alice, bob] = case.sessions().await;
            Box::pin(async move {
                let conversation = case.create_conversation([&alice, &bob]).await;

                let nb_messages = OUT_OF_ORDER_TOLERANCE * 2;
                let mut messages = vec![];

                // stack up encrypted messages..
                for i in 0..nb_messages {
                    let msg = format!("Hello {i}");
                    let encrypted = conversation.guard().await.encrypt_message(&msg).await.unwrap();
                    messages.push((msg, encrypted));
                }

                // ..then unstack them to see OUT_OF_ORDER_TOLERANCE come into play
                for (i, (original, encrypted)) in messages.iter().rev().enumerate() {
                    let decrypt = conversation.guard_of(&bob).await.decrypt_message(encrypted).await;
                    if i < OUT_OF_ORDER_TOLERANCE as usize {
                        let decrypt = decrypt.unwrap();
                        let decrypted = &decrypt.as_application_message().unwrap().plaintext;
                        assert_eq!(decrypted, original.as_bytes());
                    } else {
                        assert!(matches!(decrypt.unwrap_err(), Error::DuplicateMessage))
                    }
                }
            })
            .await
        }

        #[apply(all_cred_cipher)]
        async fn returns_sender_client_id(case: TestContext) {
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
                    .unwrap();

                let sender_client_id = &decrypted.as_application_message().unwrap().sender_client_id;
                assert_eq!(sender_client_id, &alice.get_client_id().await);
            })
            .await
        }
    }

    mod epoch_sync {
        use super::*;

        #[apply(all_cred_cipher)]
        async fn should_throw_specialized_error_when_epoch_too_old(case: TestContext) {
            let [alice, bob] = case.sessions().await;
            Box::pin(async move {
                let mut conversation = case.create_conversation([&alice, &bob]).await;

                // Alice encrypts a message to Bob
                let bob_message1 = conversation.guard().await.encrypt_message(b"Hello Bob").await.unwrap();
                let bob_message2 = conversation
                    .guard()
                    .await
                    .encrypt_message(b"Hello again Bob")
                    .await
                    .unwrap();

                // Move group's epoch forward by self updating
                for _ in 0..MAX_PAST_EPOCHS {
                    conversation = conversation.update_notify().await;
                }

                // Decrypt should work
                let decrypt = conversation
                    .guard_of(&bob)
                    .await
                    .decrypt_message(&bob_message1)
                    .await
                    .unwrap();
                assert_eq!(decrypt.as_application_message().unwrap().plaintext, b"Hello Bob");

                // Moving the epochs once more should cause an error
                let conversation = conversation.update_notify().await;

                let decrypt = conversation.guard_of(&bob).await.decrypt_message(&bob_message2).await;
                assert!(matches!(decrypt.unwrap_err(), Error::MessageEpochTooOld));
            })
            .await
        }

        #[apply(all_cred_cipher)]
        async fn should_throw_specialized_error_when_epoch_desynchronized(case: TestContext) {
            let [alice, bob, charlie] = case.sessions().await;
            Box::pin(async move {
                let conversation = case.create_conversation([&alice, &bob, &charlie]).await;

                // Alice generates a bunch of soon to be outdated messages
                let message_guard = conversation.remove_proposal(&charlie).await;
                let old_message = message_guard.message().to_bytes().unwrap();
                let conversation = message_guard.finish();
                conversation
                    .guard()
                    .await
                    .mutate_group(async |_, group, _| {
                        group.clear_pending_proposals();
                        Ok(())
                    })
                    .await
                    .unwrap();
                let commit_guard = conversation.update_unmerged().await;
                let old_commit = commit_guard.message().to_bytes().unwrap();
                let conversation = commit_guard.finish();
                conversation.guard().await.clear_pending_commit().await.unwrap();

                // Now let's jump to next epoch
                let conversation = conversation.update_notify().await;

                // trying to consume outdated messages should fail with a dedicated error
                let decrypt_err = conversation
                    .guard_of(&bob)
                    .await
                    .decrypt_message(&old_message)
                    .await
                    .unwrap_err();

                assert!(matches!(decrypt_err, Error::StaleProposal));

                let decrypt_err = conversation
                    .guard_of(&bob)
                    .await
                    .decrypt_message(&old_commit)
                    .await
                    .unwrap_err();

                assert!(matches!(decrypt_err, Error::StaleCommit));
            })
            .await
        }
    }

    mod malformed {
        use super::*;

        #[macro_rules_attribute::apply(smol_macros::test)]
        async fn too_short_message_is_a_tls_error() {
            let case = TestContext::default();
            let [alice] = case.sessions().await;
            let conversation = case.create_conversation([&alice]).await;

            // Anything shorter than 4 bytes can't hold the protocol version and wire format.
            for len in 0..4 {
                let message = vec![0; len];
                // notably, attempting to decrypt a short message produces an error, not a panic
                let decrypt_err = conversation.guard().await.decrypt_message(&message).await.unwrap_err();
                assert!(
                    matches!(decrypt_err, Error::Tls(_)),
                    "{len}-byte message: unexpected error {decrypt_err:?}"
                );
            }
        }
    }
}
