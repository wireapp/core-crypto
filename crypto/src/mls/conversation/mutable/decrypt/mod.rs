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

use std::{
    borrow::{Borrow, Cow},
    collections::VecDeque,
};

use core_crypto_keystore::entities::{InboxMessage, WaitingFor};
use log::warn;
use openmls::{
    group::MlsGroup,
    prelude::{
        Credential as MlsCredential, CredentialType, CredentialWithKey, LeafNodeIndex, Member, ProcessedMessageContent,
        ProtocolMessage, StagedCommit,
    },
};

pub(in crate::mls::conversation) use self::incoming_message::{IncomingMessage, ParsedMessage};
pub use self::outputs::{
    Commit, DecryptedBytes, DecryptedMessage, DecryptionOutcome, DeferralReason, Proposal, RejectionReason,
};
use self::{
    outputs::Effect,
    process_message::{ProcessedMessage, process_message},
};
use super::{ConversationMut, Result};
use crate::{
    E2eiConversationState, RecursiveError, Session,
    error::infrastructure::Infrastructural as _,
    mls::{
        conversation::Error,
        credential::{self, ext::CredentialExt as _, identity::credential_identity, validation::validate_credentials},
    },
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
    /// Returns a vector. The first outcome in this vector is always for the input message; subsequent outcomes
    /// are for buffered messages which have been unblocked by that first message.
    ///
    /// Errors occurred when decrypting the message with which this function was called propagate as normal.
    /// Errors occurred when decrypting buffered messages unblocked by the initial message are propagated in
    /// case they are infrastructure errors. If they are not, then they are logged but not propagated, and the
    /// related message is dropped.
    pub(crate) async fn decrypt_message(&mut self, bytes: impl Into<Cow<'_, [u8]>>) -> Result<Vec<DecryptionOutcome>> {
        let id = self.id.clone();
        let log_and_skip_unparseable_buffered_messages = move |maybe_message: Result<
            (InboxMessage, IncomingMessage),
            RejectionReason,
        >| {
            match maybe_message {
                Ok((inbox, incoming)) => Some((incoming, inbox.message.into())),
                Err(reason) => {
                    // this case should be rare given that every message is parsed before ever being inserted into the
                    // inbox
                    warn!(reason:?, group_id = id.clone(); "failed to parse buffered message while taking from inbox; dropping");
                    None
                }
            }
        };

        let bytes = bytes.into();
        let incoming_message = match IncomingMessage::parse(&bytes) {
            Ok(message) => message,
            Err(reason) => return Ok(vec![reason.into()]),
        };
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
            let content_type = message.parsed.content_type();
            let epoch = message.parsed.epoch();
            let arrival_sequence = message.arrival_sequence;
            let was_pending = self.group().await.pending_status.is_pending();

            let outcome_result = tx_context_inner
                .with_savepoint_with_outcome_check(
                    "decrypt_message",
                    async || {
                        if let Some(outcome) = self.try_resolve_pending(&message).await? {
                            return Ok(outcome);
                        }
                        match message.parsed {
                            ParsedMessage::Mls(protocol_message) => self.decrypt_mls_message(protocol_message).await,
                            ParsedMessage::Tnt(tnt_message) => self.decrypt_tnt_message(tnt_message).await,
                        }
                    },
                    Error::savepoint,
                    // deferred and rejected messages, and errors, all roll back the savepoint
                    // (deferred messages get sent to the inbox later on; this just clears potential side effects)
                    |maybe_outcome| matches!(maybe_outcome, Ok(DecryptionOutcome::Decrypted(_))),
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

            if was_pending && !self.group().await.pending_status.is_pending() {
                // we must have merged the pending group, so let's enqueue whatever in the inbox was waiting for that
                // before we even begin with the effect
                queue.extend(
                    self.inbox_take(WaitingFor::PendingJoin, None)?
                        .filter_map(&log_and_skip_unparseable_buffered_messages),
                );
            }

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

            // we exclude messages which were previously buffered and then re-deferred, because
            // callers neither know nor care about those.
            if !(arrival_sequence.is_some() && outcome.is_deferred()) {
                decrypted_messages.push(outcome);
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

    /// Attempt to resolve messages against a potentially pending group.
    ///
    /// If the group is pending, we generally need to simply defer it.
    /// In that case, returns `Some(DecryptionOutcome::Deferred(PendingJoin))`.
    ///
    /// There is one exception: if the group is pending, and the message is our own join commit, the Delivery Service
    /// has accepted it. Then we need to establish the group, returning the decryption outcome of that operation.
    ///
    /// openmls merges an external commit as soon as it builds it, so the pending group is already in the epoch our
    /// join commit starts, and its confirmation tag is that commit's.
    ///
    /// In every other case, returns `Ok(None)`.
    async fn try_resolve_pending(&mut self, message: &IncomingMessage) -> Result<Option<DecryptionOutcome>> {
        let group = self.group().await;

        if !group.pending_status.is_pending() {
            return Ok(None);
        }

        if let ParsedMessage::Mls(ProtocolMessage::PublicMessage(public_message)) = &message.parsed
            && public_message
                .confirmation_tag()
                .is_some_and(|message_tag| message_tag == group.mls_group().confirmation_tag())
        {
            drop(group);
            return self.merge_commit().await.map(Into::into).map(Some);
        }
        Ok(Some(DeferralReason::PendingJoin.into()))
    }

    /// Decrypt a single MLS message, reporting but not taking action on its outcome.
    async fn decrypt_mls_message(&mut self, message: ProtocolMessage) -> Result<DecryptionOutcome> {
        let message = match process_message(self, message).await? {
            // processing succeeded
            ProcessedMessage::Content(message) => message,

            // Handles the case where we receive our own commits.
            ProcessedMessage::OwnCommit { matches_pending_commit } => {
                let decrypted_message = self.handle_own_commit(matches_pending_commit).await?;
                return Ok(decrypted_message.into());
            }
            ProcessedMessage::Deferred(reason) => return Ok(reason.into()),
            ProcessedMessage::Rejected(reason) => return Ok(reason.into()),
        };

        let credential = CredentialWithKey {
            credential: message.credential().clone(),
            signature_key: message.signature_key().clone(),
        };
        let epoch = message.epoch();

        let pki_env = self.crypto_provider().await?.authentication_service().pki_env().await;
        let identity = credential
            .extract_identity(self.cipher_suite().await.signature_algorithm(), pki_env.as_deref())
            .await
            .map_err(RecursiveError::context("extracting identity"))?;

        // We only need this in the ProcessedMessageContent::ApplicationMessage match arm below, however, at that point
        // we cannot borrow from `message` anymore, because it is moved by `message.into_content()`.
        let sender_client_id_result = credential_identity(&credential.credential)
            .map_err(RecursiveError::mls_credential("reading the sender's identity"))
            .and_then(|identity| {
                identity
                    .as_slice()
                    .try_into()
                    .map_err(RecursiveError::context("client id from credential"))
            });

        let decrypted = match message.into_content() {
            ProcessedMessageContent::ApplicationMessage(app_msg) => {
                handle::application(self, app_msg, epoch, identity, sender_client_id_result)?
            }
            ProcessedMessageContent::ProposalMessage(proposal)
            | ProcessedMessageContent::ExternalJoinProposalMessage(proposal) => {
                return handle::proposal(self, *proposal, identity).await;
            }
            ProcessedMessageContent::StagedCommitMessage(staged_commit) => {
                return handle::staged_commit(self, *staged_commit, identity).await;
            }
            ProcessedMessageContent::OwnPendingCommit | ProcessedMessageContent::OwnPrivateMessage => {
                return Err(Error::MlsMessageInvalidState(
                    "process_message turns messages of our own into other outcomes",
                ));
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

    /// Check the credentials an incoming message brings into the conversation.
    ///
    /// A credential we can't read, or one the authentication service doesn't accept, rejects the message. Anything else
    /// that goes wrong is an error.
    async fn validate_incoming_credentials(
        &self,
        credentials: &[impl Borrow<MlsCredential> + Sync],
    ) -> Result<Option<RejectionReason>> {
        let backend = self.crypto_provider().await?;
        match validate_credentials(backend.authentication_service(), credentials).await {
            Ok(()) => Ok(None),
            Err(
                err @ (credential::Error::DecodeX509(_)
                | credential::Error::DecodeX509Chain(_)
                | credential::Error::InvalidIdentity
                | credential::Error::UnsupportedCredentialType(_)),
            ) => Ok(Some(RejectionReason::MalformedCredential(err))),
            Err(err @ credential::Error::CredentialRejected(_)) => Ok(Some(RejectionReason::UntrustedCredential(err))),
            Err(err) => Err(RecursiveError::mls_credential("checking the credentials a message brings in")(err).into()),
        }
    }

    /// Check a commit before merging it, returning why it's rejected if it is.
    async fn validate_commit(&self, commit: &StagedCommit) -> Result<Option<RejectionReason>> {
        if let Some(rejection) = self
            .validate_incoming_credentials(&commit.credentials_to_verify().collect::<Vec<_>>())
            .await?
        {
            return Ok(Some(rejection));
        }

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
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        DecryptedMessage, DecryptionOutcome, DeferralReason, RejectionReason,
        mls::conversation::config::{MAX_PAST_EPOCHS, OUT_OF_ORDER_TOLERANCE},
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
                let decrypted = decrypted.unwrap().into_single_decrypted();
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
                let decrypted = decrypted.unwrap().into_single_decrypted();
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
                let decrypted = decrypted.unwrap().into_single_decrypted();

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

                assert!(decrypted.unwrap().into_single_decrypted().as_commit().is_some());
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

                assert!(decrypted.unwrap().into_single_decrypted().as_proposal().is_some());
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
                    .unwrap()
                    .into_single_decrypted();
                let dec_msg = &decrypted.as_application_message().unwrap().plaintext;
                assert_eq!(dec_msg, msg);
                assert!(!bob_observer.has_changed().await);
                alice
                    .verify_sender_identity(&case, &alice.initial_credential, &decrypted)
                    .await;

                let msg = b"Hello alice";
                let encrypted = conversation.guard_of(&bob).await.encrypt_message(msg).await.unwrap();
                assert_ne!(&msg[..], &encrypted[..]);
                let decrypted = conversation
                    .guard()
                    .await
                    .decrypt_message(encrypted)
                    .await
                    .unwrap()
                    .into_single_decrypted();
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
                assert!(matches!(
                    decrypt.unwrap().into_single_rejected(),
                    RejectionReason::InvalidAuthentication
                ));
            })
            .await
        }

        #[apply(all_cred_cipher)]
        async fn future_epoch_app_message_is_deferred_until_its_commit(case: TestContext) {
            let [alice, bob] = case.sessions().await;
            Box::pin(async move {
                let conversation = case.create_conversation([&alice, &bob]).await;

                // only Alice will change epoch without notifying Bob
                let commit_guard = conversation.update().await;
                let conversation = commit_guard.conversation();

                // Now in epoch 2 Alice will encrypt a message
                let msg = b"Hello bob";
                let encrypted = conversation.guard().await.encrypt_message(msg).await.unwrap();

                // which Bob cannot decrypt because he won't have epoch 2 keys until he receives the commit
                let decrypt = conversation.guard_of(&bob).await.decrypt_message(encrypted).await;
                assert!(
                    matches!(
                        decrypt.unwrap().into_single_deferred(),
                        DeferralReason::FutureEpoch { .. }
                    ),
                    "the message must have been deferred"
                );

                // once the commit arrives, the buffered message is decrypted right after it
                let (_, decrypted) = commit_guard.notify_member_fallible(&bob).await;
                let decrypted = decrypted.unwrap();
                let [
                    DecryptionOutcome::Decrypted(DecryptedMessage::Commit(_)),
                    DecryptionOutcome::Decrypted(DecryptedMessage::ApplicationMessage(decrypted_msg)),
                ] = decrypted.as_slice()
                else {
                    panic!("expected the commit, then the buffered message: {decrypted:?}");
                };
                assert_eq!(&decrypted_msg.plaintext, msg);
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
                        let decrypt = decrypt.unwrap().into_single_decrypted();
                        let decrypted = &decrypt.as_application_message().unwrap().plaintext;
                        assert_eq!(decrypted, original.as_bytes());
                    } else {
                        // too far behind to decrypt, and never decrypted, so not a duplicate
                        assert!(matches!(
                            decrypt.unwrap().into_single_rejected(),
                            RejectionReason::MessageEpochTooOld { .. }
                        ))
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
                    .unwrap()
                    .into_single_decrypted();

                let sender_client_id = &decrypted.as_application_message().unwrap().sender_client_id;
                assert_eq!(sender_client_id, &alice.get_client_id().await);
            })
            .await
        }

        #[apply(all_cred_cipher)]
        async fn app_message_from_a_member_removed_since_names_its_sender(case: TestContext) {
            let [alice, bob, charlie] = case.sessions().await;
            let conversation = case.create_conversation([&alice, &bob, &charlie]).await;

            let encrypted = conversation
                .guard_of(&charlie)
                .await
                .encrypt_message(b"Hello from the previous epoch")
                .await
                .unwrap();
            let conversation = conversation.remove_notify(&charlie).await;

            let decrypted = conversation
                .guard_of(&bob)
                .await
                .decrypt_message(encrypted)
                .await
                .unwrap()
                .into_single_decrypted();

            let message = decrypted.as_application_message().unwrap();
            assert_eq!(message.plaintext, b"Hello from the previous epoch");
            assert_eq!(message.sender_client_id, charlie.get_client_id().await);
        }
    }

    mod epoch_sync {
        use openmls_traits::OpenMlsProvider as _;

        use super::*;
        use crate::mls::conversation::config::MAX_FUTURE_EPOCHS;

        #[apply(all_cred_cipher)]
        async fn should_reject_message_when_epoch_too_far_in_the_future(case: TestContext) {
            let [alice, bob] = case.sessions().await;
            let conversation = case.create_conversation([&alice, &bob]).await;

            // Alice commits twice without Bob hearing of it, so she is two epochs ahead of him.
            let conversation = conversation.update().await.finish().update().await.finish();
            let message_epoch = conversation.guard().await.epoch().await;
            let group_epoch = conversation.guard_of(&bob).await.epoch().await;
            assert!(
                message_epoch > group_epoch + MAX_FUTURE_EPOCHS,
                "the test is only meaningful if the message is beyond the epochs we buffer"
            );

            let encrypted = conversation.guard().await.encrypt_message(b"too soon").await.unwrap();
            let reason = conversation
                .guard_of(&bob)
                .await
                .decrypt_message(&encrypted)
                .await
                .unwrap()
                .into_single_rejected();
            let RejectionReason::UnbufferedFarFutureMessage {
                message_epoch: reported_message_epoch,
                group_epoch: reported_group_epoch,
            } = reason
            else {
                panic!("a message beyond the epochs we buffer must be rejected, got {reason:?}");
            };
            assert_eq!(
                reported_message_epoch, message_epoch,
                "the rejection must report the message's epoch"
            );
            assert_eq!(
                reported_group_epoch, group_epoch,
                "the rejection must report the group's epoch"
            );
            assert_eq!(
                bob.transaction.count_entities().await.pending_messages,
                0,
                "a rejected message must not be buffered"
            );
        }

        #[apply(all_cred_cipher)]
        async fn should_reject_message_when_epoch_too_old(case: TestContext) {
            let [alice, bob] = case.sessions().await;
            Box::pin(async move {
                let mut conversation = case.create_conversation([&alice, &bob]).await;

                // Alice encrypts a message to Bob
                let message_epoch = conversation.guard().await.epoch().await;
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
                assert_eq!(
                    decrypt
                        .into_single_decrypted()
                        .as_application_message()
                        .unwrap()
                        .plaintext,
                    b"Hello Bob"
                );

                // Moving the epochs once more should cause an error
                let conversation = conversation.update_notify().await;

                let group_epoch = conversation.guard_of(&bob).await.epoch().await;
                let reason = conversation
                    .guard_of(&bob)
                    .await
                    .decrypt_message(&bob_message2)
                    .await
                    .unwrap()
                    .into_single_rejected();
                let RejectionReason::MessageEpochTooOld {
                    message_epoch: reported_message_epoch,
                    group_epoch: reported_group_epoch,
                } = reason
                else {
                    panic!("a message from an epoch beyond retention must be rejected as too old, got {reason:?}");
                };
                assert_eq!(
                    reported_message_epoch, message_epoch,
                    "the rejection must report the message's epoch"
                );
                assert_eq!(
                    reported_group_epoch, group_epoch,
                    "the rejection must report the group's epoch"
                );
            })
            .await
        }

        #[apply(all_cred_cipher)]
        async fn should_reject_outdated_messages_when_epoch_desynchronized(case: TestContext) {
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
                    .mutate_group(async |provider, group, _| {
                        group
                            .clear_pending_proposals(provider.storage())
                            .map_err(crate::KeystoreError::wrap("clearing pending proposals"))?;
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
                    .unwrap()
                    .into_single_rejected();

                assert!(matches!(decrypt_err, RejectionReason::StaleProposal));

                let decrypt_err = conversation
                    .guard_of(&bob)
                    .await
                    .decrypt_message(&old_commit)
                    .await
                    .unwrap()
                    .into_single_rejected();

                assert!(matches!(decrypt_err, RejectionReason::StaleCommit));
            })
            .await
        }
    }

    mod malformed {
        use super::*;

        // Anything shorter than 4 bytes can't hold the protocol version and wire format.
        #[rstest]
        #[test_attr(macro_rules_attribute::apply(smol_macros::test))]
        #[case(0)]
        #[case(1)]
        #[case(2)]
        #[case(3)]
        async fn too_short_message_is_rejected_as_unparseable(#[case] len: usize) {
            let case = TestContext::default();
            let [alice] = case.sessions().await;
            let conversation = case.create_conversation([&alice]).await;

            let message = vec![0; len];
            let reason = conversation
                .guard()
                .await
                .decrypt_message(&message)
                .await
                .unwrap()
                .into_single_rejected();
            assert!(
                matches!(reason, RejectionReason::Unparseable(_)),
                "{len}-byte message: unexpected rejection {reason:?}"
            );
        }
    }
}
