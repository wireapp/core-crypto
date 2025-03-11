//! MLS defines 3 kind of messages: Proposal, Commits and Application messages. Since they can (should)
//! be all encrypted we need to first decrypt them before deciding what to do with them.
//!
//! This table summarizes when a MLS group can decrypt any message:
//!
//! | can decrypt ?     | 0 pend. Commit | 1 pend. Commit |
//! |-------------------|----------------|----------------|
//! | 0 pend. Proposal  | ✅              | ✅              |
//! | 1+ pend. Proposal | ✅              | ✅              |

mod buffer_commit;
pub(crate) mod buffer_messages;

use super::{ConversationGuard, Result};
use crate::e2e_identity::conversation_state::compute_state;
use crate::e2e_identity::init_certificates::NewCrlDistributionPoint;
use crate::mls::conversation::renew::Renew;
use crate::mls::conversation::{Conversation, ConversationWithMls, Error};
use crate::mls::credential::crl::{
    extract_crl_uris_from_proposals, extract_crl_uris_from_update_path, get_new_crl_distribution_points,
};
use crate::mls::credential::ext::CredentialExt as _;
use crate::obfuscate::Obfuscated;
use crate::prelude::{ClientId, E2eiConversationState};
use crate::prelude::{MlsProposalBundle, WireIdentity};
use crate::{MlsError, RecursiveError};
use log::{debug, info};
use openmls::framing::errors::{MessageDecryptionError, SecretTreeError};
use openmls::framing::{MlsMessageIn, MlsMessageInBody, ProcessedMessage, ProtocolMessage};
use openmls::prelude::{
    ContentType, CredentialType, ProcessMessageError, ProcessedMessageContent, Proposal, StageCommitError,
    StagedCommit, ValidationError,
};
use openmls_traits::OpenMlsCryptoProvider as _;
use tls_codec::Deserialize as _;

/// Represents the potential items a consumer might require after passing us an encrypted message we
/// have decrypted for him
#[derive(Debug)]
pub struct MlsConversationDecryptMessage {
    /// Decrypted text message
    pub app_msg: Option<Vec<u8>>,
    /// Only when decrypted message is a commit, CoreCrypto will renew local proposal which could not make it in the commit.
    /// This will contain either:
    /// * local pending proposal not in the accepted commit
    /// * If there is a pending commit, its proposals which are not in the accepted commit
    pub proposals: Vec<MlsProposalBundle>,
    /// Is the conversation still active after receiving this commit aka has the user been removed from the group
    pub is_active: bool,
    /// Delay time in seconds to feed caller timer for committing
    pub delay: Option<u64>,
    /// [ClientId] of the sender of the message being decrypted. Only present for application messages.
    pub sender_client_id: Option<ClientId>,
    /// Is the epoch changed after decrypting this message
    #[deprecated = "This member will be removed in the future. Prefer using the `EpochObserver` interface."]
    pub has_epoch_changed: bool,
    /// Identity claims present in the sender credential
    /// Present for all messages
    pub identity: WireIdentity,
    /// Only set when the decrypted message is a commit.
    /// Contains buffered messages for next epoch which were received before the commit creating the epoch
    /// because the DS did not fan them out in order.
    pub buffered_messages: Option<Vec<MlsBufferedConversationDecryptMessage>>,
    /// New CRL distribution points that appeared by the introduction of a new credential
    pub crl_new_distribution_points: NewCrlDistributionPoint,
}

/// Type safe recursion of [MlsConversationDecryptMessage]
#[derive(Debug)]
pub struct MlsBufferedConversationDecryptMessage {
    /// see [MlsConversationDecryptMessage]
    pub app_msg: Option<Vec<u8>>,
    /// see [MlsConversationDecryptMessage]
    pub proposals: Vec<MlsProposalBundle>,
    /// see [MlsConversationDecryptMessage]
    pub is_active: bool,
    /// see [MlsConversationDecryptMessage]
    pub delay: Option<u64>,
    /// see [MlsConversationDecryptMessage]
    pub sender_client_id: Option<ClientId>,
    /// see [MlsConversationDecryptMessage]
    #[deprecated = "This member will be removed in the future. Prefer using the `EpochObserver` interface."]
    pub has_epoch_changed: bool,
    /// see [MlsConversationDecryptMessage]
    pub identity: WireIdentity,
    /// see [MlsConversationDecryptMessage]
    pub crl_new_distribution_points: NewCrlDistributionPoint,
}

impl From<MlsConversationDecryptMessage> for MlsBufferedConversationDecryptMessage {
    fn from(from: MlsConversationDecryptMessage) -> Self {
        // we still support the `has_epoch_changed` field, though we'll remove it later
        #[expect(deprecated)]
        Self {
            app_msg: from.app_msg,
            proposals: from.proposals,
            is_active: from.is_active,
            delay: from.delay,
            sender_client_id: from.sender_client_id,
            has_epoch_changed: from.has_epoch_changed,
            identity: from.identity,
            crl_new_distribution_points: from.crl_new_distribution_points,
        }
    }
}

struct ParsedMessage {
    is_duplicate: bool,
    protocol_message: ProtocolMessage,
    content_type: ContentType,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum RecursionPolicy {
    AsNecessary,
    None,
}

impl ConversationGuard {
    /// Deserializes a TLS-serialized message, then processes it
    ///
    /// # Arguments
    /// * `message` - the encrypted message as a byte array
    ///
    /// # Returns
    /// An [MlsConversationDecryptMessage]
    ///
    /// # Errors
    /// If a message has been buffered, this will be indicated by an error.
    /// Other errors are originating from OpenMls and the KeyStore
    pub async fn decrypt_message(&mut self, message: impl AsRef<[u8]>) -> Result<MlsConversationDecryptMessage> {
        let mls_message_in =
            MlsMessageIn::tls_deserialize(&mut message.as_ref()).map_err(Error::tls_deserialize("mls message in"))?;

        let decrypt_message_result = self
            .decrypt_message_inner(mls_message_in, RecursionPolicy::AsNecessary)
            .await;

        // In the inner `decrypt_message` above, we raise the `BufferedCommit` or
        // `BufferedFutureMessage` errors, but we only handle them here.
        // That's because in the scope they're raised, we don't have access to the raw message
        // bytes; here, we do.
        if let Err(Error::BufferedFutureMessage { message_epoch }) = decrypt_message_result {
            self.buffer_future_message(message.as_ref()).await?;
            let conversation = self.conversation().await;
            info!(group_id = Obfuscated::from(conversation.id()); "Buffered future message from epoch {message_epoch}");
        }
        if let Err(Error::BufferedCommit) = decrypt_message_result {
            self.buffer_commit(message).await?;
        }

        let decrypt_message = decrypt_message_result?;

        if !decrypt_message.is_active {
            self.wipe().await?;
        }
        Ok(decrypt_message)
    }

    /// We need an inner part, because this may be called recursively.
    async fn decrypt_message_inner(
        &mut self,
        message: MlsMessageIn,
        recursion_policy: RecursionPolicy,
    ) -> Result<MlsConversationDecryptMessage> {
        let client = &self.mls_client().await?;
        let backend = &self.mls_provider().await?;
        let parsed_message = self.parse_message(message.clone()).await?;

        let message_result = self.process_message(parsed_message).await;

        // Handles the case where we receive our own commits.
        if let Err(Error::Mls(crate::MlsError {
            source:
                crate::MlsErrorKind::MlsMessageError(ProcessMessageError::InvalidCommit(StageCommitError::OwnCommit)),
            ..
        })) = message_result
        {
            let mut conversation = self.conversation_mut().await;
            let ct = conversation.extract_confirmation_tag_from_own_commit(&message)?;
            let mut decrypted_message = conversation.handle_own_commit(client, backend, ct).await?;
            debug_assert!(
                decrypted_message.buffered_messages.is_none(),
                "decrypted message should be constructed with empty buffer"
            );
            if recursion_policy == RecursionPolicy::AsNecessary {
                drop(conversation);
                decrypted_message.buffered_messages = self.restore_and_clear_pending_messages().await?;
            }

            return Ok(decrypted_message);
        }

        // In this error case, we have a missing proposal, so we need to buffer the commit.
        // We can't do that here--we don't have the appropriate data in scope--but we can at least
        // produce the proper error and return that, so our caller can handle it.
        if let Err(Error::Mls(crate::MlsError {
            source:
                crate::MlsErrorKind::MlsMessageError(ProcessMessageError::InvalidCommit(StageCommitError::MissingProposal)),
            ..
        })) = message_result
        {
            return Err(Error::BufferedCommit);
        }

        let message = message_result?;

        let credential = message.credential();
        let epoch = message.epoch();

        let identity = credential
            .extract_identity(
                self.ciphersuite().await,
                backend.authentication_service().borrow().await.as_ref(),
            )
            .map_err(RecursiveError::mls_credential("extracting identity"))?;

        let sender_client_id: ClientId = credential.credential.identity().into();

        let decrypted = match message.into_content() {
            ProcessedMessageContent::ApplicationMessage(app_msg) => {
                let conversation = self.conversation().await;
                debug!(
                    group_id = Obfuscated::from(&conversation.id),
                    epoch = epoch.as_u64(),
                    sender_client_id = Obfuscated::from(&sender_client_id);
                    "Application message"
                );

                // we still support the `has_epoch_changed` field, though we'll remove it later
                #[expect(deprecated)]
                MlsConversationDecryptMessage {
                    app_msg: Some(app_msg.into_bytes()),
                    proposals: vec![],
                    is_active: true,
                    delay: None,
                    sender_client_id: Some(sender_client_id),
                    has_epoch_changed: false,
                    identity,
                    buffered_messages: None,
                    crl_new_distribution_points: None.into(),
                }
            }
            ProcessedMessageContent::ProposalMessage(proposal) => {
                let mut conversation = self.conversation_mut().await;
                let crl_dps = extract_crl_uris_from_proposals(&[proposal.proposal().clone()])
                    .map_err(RecursiveError::mls_credential("extracting crl urls from proposals"))?;
                let crl_new_distribution_points = get_new_crl_distribution_points(backend, crl_dps)
                    .await
                    .map_err(RecursiveError::mls_credential("getting new crl distribution points"))?;

                info!(
                    group_id = Obfuscated::from(&conversation.id),
                    sender = Obfuscated::from(proposal.sender()),
                    proposals = Obfuscated::from(&proposal.proposal);
                    "Received proposal"
                );

                conversation.group.store_pending_proposal(*proposal);
                drop(conversation);
                if let Some(commit) =
                    self.retrieve_buffered_commit()
                        .await
                        .map_err(RecursiveError::mls_conversation(
                            "retrieving buffered commit while handling proposal",
                        ))?
                {
                    let process_result = self.try_process_buffered_commit(commit, recursion_policy).await;

                    if process_result.is_ok() {
                        self.clear_buffered_commit()
                            .await
                            .map_err(RecursiveError::mls_conversation(
                                "clearing buffered commit after successful application",
                            ))?;
                    }
                    // If we got back a buffered commit error, then we still don't have enough proposals.
                    // In that case, we want to just proceed as normal for this proposal.
                    //
                    // In any other case, the result from the commit overrides the result from the proposal.
                    if !matches!(process_result, Err(Error::BufferedCommit)) {
                        // either the commit applied successfully, in which case its return value
                        // should override the return value from the proposal, or it raised some kind
                        // of error, in which case the caller needs to know about that.
                        return process_result
                            .map_err(RecursiveError::mls_conversation("processing buffered commit"))
                            .map_err(Into::into);
                    }
                }

                let conversation = self.conversation().await;
                let delay = conversation.compute_next_commit_delay();

                // we still support the `has_epoch_changed` field, though we'll remove it later
                #[expect(deprecated)]
                MlsConversationDecryptMessage {
                    app_msg: None,
                    proposals: vec![],
                    is_active: true,
                    delay,
                    sender_client_id: None,
                    has_epoch_changed: false,
                    identity,
                    buffered_messages: None,
                    crl_new_distribution_points,
                }
            }
            ProcessedMessageContent::StagedCommitMessage(staged_commit) => {
                self.validate_commit(&staged_commit).await?;
                let mut conversation = self.conversation_mut().await;

                let pending_proposals = conversation.self_pending_proposals().cloned().collect::<Vec<_>>();

                let proposal_refs: Vec<Proposal> = pending_proposals
                    .iter()
                    .map(|p| p.proposal().clone())
                    .chain(
                        staged_commit
                            .add_proposals()
                            .map(|p| Proposal::Add(p.add_proposal().clone())),
                    )
                    .chain(
                        staged_commit
                            .update_proposals()
                            .map(|p| Proposal::Update(p.update_proposal().clone())),
                    )
                    .collect();

                // - This requires a change in OpenMLS to get access to it
                let mut crl_dps = extract_crl_uris_from_proposals(&proposal_refs)
                    .map_err(RecursiveError::mls_credential("extracting crl urls from proposals"))?;
                crl_dps.extend(
                    extract_crl_uris_from_update_path(&staged_commit)
                        .map_err(RecursiveError::mls_credential("extracting crl urls from update path"))?,
                );

                let crl_new_distribution_points = get_new_crl_distribution_points(backend, crl_dps)
                    .await
                    .map_err(RecursiveError::mls_credential("getting new crl distribution points"))?;

                // getting the pending has to be done before `merge_staged_commit` otherwise it's wiped out
                let pending_commit = conversation.group.pending_commit().cloned();

                conversation
                    .group
                    .merge_staged_commit(backend, *staged_commit.clone())
                    .await
                    .map_err(MlsError::wrap("merge staged commit"))?;

                let (proposals_to_renew, needs_update) = Renew::renew(
                    &conversation.group.own_leaf_index(),
                    pending_proposals.into_iter(),
                    pending_commit.as_ref(),
                    staged_commit.as_ref(),
                );
                let proposals = conversation
                    .renew_proposals_for_current_epoch(client, backend, proposals_to_renew.into_iter(), needs_update)
                    .await?;

                // can't use `.then` because async
                let mut buffered_messages = None;
                // drop conversation to allow borrowing `self` again
                drop(conversation);
                if recursion_policy == RecursionPolicy::AsNecessary {
                    buffered_messages = self.restore_and_clear_pending_messages().await?;
                }

                let conversation = self.conversation().await;
                let epoch = staged_commit.staged_context().epoch().as_u64();
                info!(
                    group_id = Obfuscated::from(&conversation.id),
                    epoch,
                    proposals:? = staged_commit.queued_proposals().map(Obfuscated::from).collect::<Vec<_>>();
                    "Epoch advanced"
                );
                client.notify_epoch_changed(conversation.id.clone(), epoch).await;

                // we still support the `has_epoch_changed` field, though we'll remove it later
                #[expect(deprecated)]
                MlsConversationDecryptMessage {
                    app_msg: None,
                    proposals,
                    is_active: conversation.group.is_active(),
                    delay: conversation.compute_next_commit_delay(),
                    sender_client_id: None,
                    has_epoch_changed: true,
                    identity,
                    buffered_messages,
                    crl_new_distribution_points,
                }
            }
            ProcessedMessageContent::ExternalJoinProposalMessage(proposal) => {
                let mut conversation = self.conversation_mut().await;
                info!(
                    group_id = Obfuscated::from(&conversation.id),
                    sender = Obfuscated::from(proposal.sender());
                    "Received external join proposal"
                );

                let crl_dps = extract_crl_uris_from_proposals(&[proposal.proposal().clone()])
                    .map_err(RecursiveError::mls_credential("extracting crl uris from proposals"))?;
                let crl_new_distribution_points = get_new_crl_distribution_points(backend, crl_dps)
                    .await
                    .map_err(RecursiveError::mls_credential("getting new crl distribution points"))?;
                conversation.group.store_pending_proposal(*proposal);

                // we still support the `has_epoch_changed` field, though we'll remove it later
                #[expect(deprecated)]
                MlsConversationDecryptMessage {
                    app_msg: None,
                    proposals: vec![],
                    is_active: true,
                    delay: conversation.compute_next_commit_delay(),
                    sender_client_id: None,
                    has_epoch_changed: false,
                    identity,
                    buffered_messages: None,
                    crl_new_distribution_points,
                }
            }
        };

        let mut conversation = self.conversation_mut().await;

        conversation
            .persist_group_when_changed(&backend.keystore(), false)
            .await?;

        Ok(decrypted)
    }

    async fn parse_message(&self, msg_in: MlsMessageIn) -> Result<ParsedMessage> {
        let mut is_duplicate = false;
        let conversation = self.conversation().await;
        let backend = self.mls_provider().await?;
        let (protocol_message, content_type) = match msg_in.extract() {
            MlsMessageInBody::PublicMessage(m) => {
                is_duplicate = conversation.is_duplicate_message(&backend, &m)?;
                let ct = m.content_type();
                (ProtocolMessage::PublicMessage(m), ct)
            }
            MlsMessageInBody::PrivateMessage(m) => {
                let ct = m.content_type();
                (ProtocolMessage::PrivateMessage(m), ct)
            }
            _ => {
                return Err(
                    MlsError::wrap("parsing inbound message")(ProcessMessageError::IncompatibleWireFormat).into(),
                );
            }
        };
        Ok(ParsedMessage {
            is_duplicate,
            protocol_message,
            content_type,
        })
    }

    async fn process_message(
        &mut self,
        ParsedMessage {
            is_duplicate,
            protocol_message,
            content_type,
        }: ParsedMessage,
    ) -> Result<ProcessedMessage> {
        let msg_epoch = protocol_message.epoch().as_u64();
        let backend = self.mls_provider().await?;
        let mut conversation = self.conversation_mut().await;
        let group_epoch = conversation.group.epoch().as_u64();
        let processed_msg = conversation
            .group
            .process_message(&backend, protocol_message)
            .await
            .map_err(|e| match e {
                ProcessMessageError::ValidationError(ValidationError::UnableToDecrypt(
                    MessageDecryptionError::GenerationOutOfBound,
                )) => Error::DuplicateMessage,
                ProcessMessageError::ValidationError(ValidationError::WrongEpoch) => {
                    if is_duplicate {
                        Error::DuplicateMessage
                    } else if msg_epoch == group_epoch + 1 {
                        // limit to next epoch otherwise if we were buffering a commit for epoch + 2
                        // we would fail when trying to decrypt it in [MlsCentral::commit_accepted]

                        // We need to buffer the message until the group has advanced to the right
                        // epoch. We can't do that here--we don't have the appropriate data in scope
                        // --but we can at least produce the proper error and return that, so our
                        // caller can handle it. Our caller needs to know about the epoch number, so
                        // we pass it back inside the error.
                        Error::BufferedFutureMessage {
                            message_epoch: msg_epoch,
                        }
                    } else if msg_epoch < group_epoch {
                        match content_type {
                            ContentType::Application => Error::StaleMessage,
                            ContentType::Commit => Error::StaleCommit,
                            ContentType::Proposal => Error::StaleProposal,
                        }
                    } else {
                        Error::UnbufferedFarFutureMessage
                    }
                }
                ProcessMessageError::ValidationError(ValidationError::UnableToDecrypt(
                    MessageDecryptionError::AeadError,
                )) => Error::DecryptionError,
                ProcessMessageError::ValidationError(ValidationError::UnableToDecrypt(
                    MessageDecryptionError::SecretTreeError(SecretTreeError::TooDistantInThePast),
                )) => Error::MessageEpochTooOld,
                _ => MlsError::wrap("processing message")(e).into(),
            })?;
        if is_duplicate {
            return Err(Error::DuplicateMessage);
        }
        Ok(processed_msg)
    }

    async fn validate_commit(&self, commit: &StagedCommit) -> Result<()> {
        let backend = self.mls_provider().await?;
        if backend.authentication_service().is_env_setup().await {
            let credentials: Vec<_> = commit
                .add_proposals()
                .filter_map(|add_proposal| {
                    let credential = add_proposal.add_proposal().key_package().leaf_node().credential();

                    matches!(credential.credential_type(), CredentialType::X509).then(|| credential.clone())
                })
                .collect();
            let state = compute_state(
                self.ciphersuite().await,
                credentials.iter(),
                crate::prelude::MlsCredentialType::X509,
                backend.authentication_service().borrow().await.as_ref(),
            )
            .await;
            if state != E2eiConversationState::Verified {
                // FIXME: Uncomment when PKI env can be seeded - the computation is still done to assess performance and impact of the validations. Tracking issue: WPB-9665
                // return Err(Error::InvalidCertificateChain);
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use wasm_bindgen_test::*;

    use crate::{
        mls::conversation::{config::MAX_PAST_EPOCHS, error::Error},
        test_utils::*,
    };

    use super::*;

    wasm_bindgen_test_configure!(run_in_browser);

    mod is_active {
        use super::*;

        #[apply(all_cred_cipher)]
        #[wasm_bindgen_test]
        pub async fn decrypting_a_regular_commit_should_leave_conversation_active(case: TestCase) {
            run_test_with_client_ids(case.clone(), ["alice", "bob"], move |[alice_central, bob_central]| {
                Box::pin(async move {
                    let id = conversation_id();
                    alice_central
                        .context
                        .new_conversation(&id, case.credential_type, case.cfg.clone())
                        .await
                        .unwrap();
                    alice_central.invite_all(&case, &id, [&bob_central]).await.unwrap();

                    bob_central
                        .context
                        .conversation(&id)
                        .await
                        .unwrap()
                        .update_key_material()
                        .await
                        .unwrap();
                    let commit = bob_central.mls_transport.latest_commit().await;
                    let MlsConversationDecryptMessage { is_active, .. } = alice_central
                        .context
                        .conversation(&id)
                        .await
                        .unwrap()
                        .decrypt_message(commit.to_bytes().unwrap())
                        .await
                        .unwrap();
                    assert!(is_active)
                })
            })
            .await
        }

        #[apply(all_cred_cipher)]
        #[wasm_bindgen_test]
        pub async fn decrypting_a_commit_removing_self_should_set_conversation_inactive(case: TestCase) {
            run_test_with_client_ids(case.clone(), ["alice", "bob"], move |[alice_central, bob_central]| {
                Box::pin(async move {
                    let id = conversation_id();
                    alice_central
                        .context
                        .new_conversation(&id, case.credential_type, case.cfg.clone())
                        .await
                        .unwrap();
                    alice_central.invite_all(&case, &id, [&bob_central]).await.unwrap();

                    bob_central
                        .context
                        .conversation(&id)
                        .await
                        .unwrap()
                        .remove_members(&[alice_central.get_client_id().await])
                        .await
                        .unwrap();
                    let commit = bob_central.mls_transport.latest_commit().await;
                    let MlsConversationDecryptMessage { is_active, .. } = alice_central
                        .context
                        .conversation(&id)
                        .await
                        .unwrap()
                        .decrypt_message(commit.to_bytes().unwrap())
                        .await
                        .unwrap();
                    assert!(!is_active)
                })
            })
            .await
        }
    }

    mod commit {
        use super::*;

        #[apply(all_cred_cipher)]
        #[wasm_bindgen_test]
        pub async fn decrypting_a_commit_should_succeed(case: TestCase) {
            run_test_with_client_ids(case.clone(), ["alice", "bob"], move |[alice_central, bob_central]| {
                Box::pin(async move {
                    let id = conversation_id();
                    alice_central
                        .context
                        .new_conversation(&id, case.credential_type, case.cfg.clone())
                        .await
                        .unwrap();
                    alice_central.invite_all(&case, &id, [&bob_central]).await.unwrap();

                    let bob_observer = TestEpochObserver::new();
                    bob_central
                        .client()
                        .await
                        .register_epoch_observer(bob_observer.clone())
                        .await
                        .unwrap();

                    let epoch_before = alice_central.context.conversation(&id).await.unwrap().epoch().await;

                    alice_central
                        .context
                        .conversation(&id)
                        .await
                        .unwrap()
                        .update_key_material()
                        .await
                        .unwrap();
                    let commit = alice_central.mls_transport.latest_commit().await;

                    let decrypted = bob_central
                        .context
                        .conversation(&id)
                        .await
                        .unwrap()
                        .decrypt_message(commit.to_bytes().unwrap())
                        .await
                        .unwrap();
                    let epoch_after = bob_central.context.conversation(&id).await.unwrap().epoch().await;
                    assert_eq!(epoch_after, epoch_before + 1);
                    assert!(bob_observer.has_changed().await);
                    assert!(decrypted.delay.is_none());
                    assert!(decrypted.app_msg.is_none());

                    alice_central.verify_sender_identity(&case, &decrypted).await;
                })
            })
            .await
        }

        #[apply(all_cred_cipher)]
        #[wasm_bindgen_test]
        pub async fn decrypting_a_commit_should_not_renew_proposals_in_valid_commit(case: TestCase) {
            run_test_with_client_ids(
                case.clone(),
                ["alice", "bob", "charlie"],
                move |[mut alice_central, bob_central, charlie_central]| {
                    Box::pin(async move {
                        let id = conversation_id();
                        alice_central
                            .context
                            .new_conversation(&id, case.credential_type, case.cfg.clone())
                            .await
                            .unwrap();
                        alice_central.invite_all(&case, &id, [&bob_central]).await.unwrap();

                        let alice_observer = TestEpochObserver::new();
                        alice_central
                            .client()
                            .await
                            .register_epoch_observer(alice_observer.clone())
                            .await
                            .unwrap();

                        // Bob will create a proposal to add Charlie
                        // Alice will decrypt this proposal
                        // Then Bob will create a commit to update
                        // Alice will decrypt the commit but musn't renew the proposal to add Charlie
                        let charlie_kp = charlie_central.get_one_key_package(&case).await;

                        let add_charlie_proposal = bob_central.context.new_add_proposal(&id, charlie_kp).await.unwrap();
                        alice_central
                            .context
                            .conversation(&id)
                            .await
                            .unwrap()
                            .decrypt_message(add_charlie_proposal.proposal.to_bytes().unwrap())
                            .await
                            .unwrap();

                        alice_observer.reset().await;

                        bob_central
                            .context
                            .conversation(&id)
                            .await
                            .unwrap()
                            .update_key_material()
                            .await
                            .unwrap();
                        let commit = bob_central.mls_transport.latest_commit().await;
                        let MlsConversationDecryptMessage { proposals, delay, .. } = alice_central
                            .context
                            .conversation(&id)
                            .await
                            .unwrap()
                            .decrypt_message(commit.to_bytes().unwrap())
                            .await
                            .unwrap();
                        assert!(proposals.is_empty());
                        assert!(delay.is_none());
                        assert!(alice_central.pending_proposals(&id).await.is_empty());
                        assert!(alice_observer.has_changed().await);
                    })
                },
            )
            .await
        }

        // orphan proposal = not backed by the pending commit
        #[apply(all_cred_cipher)]
        #[wasm_bindgen_test]
        pub async fn decrypting_a_commit_should_renew_orphan_pending_proposals(case: TestCase) {
            run_test_with_client_ids(
                case.clone(),
                ["alice", "bob", "charlie"],
                move |[mut alice_central, mut bob_central, charlie_central]| {
                    Box::pin(async move {
                        let id = conversation_id();
                        alice_central
                            .context
                            .new_conversation(&id, case.credential_type, case.cfg.clone())
                            .await
                            .unwrap();
                        alice_central.invite_all(&case, &id, [&bob_central]).await.unwrap();

                        let alice_observer = TestEpochObserver::new();
                        alice_central
                            .client()
                            .await
                            .register_epoch_observer(alice_observer.clone())
                            .await
                            .unwrap();

                        // Alice will create a proposal to add Charlie
                        // Bob will create a commit which Alice will decrypt
                        // Then Alice will renew her proposal
                        bob_central
                            .context
                            .conversation(&id)
                            .await
                            .unwrap()
                            .update_key_material()
                            .await
                            .unwrap();
                        let bob_commit = bob_central.mls_transport.latest_commit().await;
                        let commit_epoch = bob_commit.epoch().unwrap();

                        // Alice propose to add Charlie
                        let charlie_kp = charlie_central.get_one_key_package(&case).await;
                        alice_central.context.new_add_proposal(&id, charlie_kp).await.unwrap();
                        assert_eq!(alice_central.pending_proposals(&id).await.len(), 1);

                        // But first she receives Bob commit
                        let MlsConversationDecryptMessage { proposals, delay, .. } = alice_central
                            .context
                            .conversation(&id)
                            .await
                            .unwrap()
                            .decrypt_message(bob_commit.to_bytes().unwrap())
                            .await
                            .unwrap();
                        // So Charlie has not been added to the group
                        assert!(
                            !alice_central
                                .get_conversation_unchecked(&id)
                                .await
                                .members()
                                .contains_key(b"charlie".as_slice())
                        );
                        // Make sure we are suggesting a commit delay
                        assert!(delay.is_some());

                        // But its proposal to add Charlie has been renewed and is also in store
                        assert!(!proposals.is_empty());
                        assert_eq!(alice_central.pending_proposals(&id).await.len(), 1);
                        let renewed_proposal = proposals.first().unwrap();
                        assert_eq!(
                            commit_epoch.as_u64() + 1,
                            renewed_proposal.proposal.epoch().unwrap().as_u64()
                        );

                        // we don't care if there was an epoch change before this,
                        // but we want to see if the epoch changes for alice now
                        alice_observer.reset().await;

                        // Let's use this proposal to see if it works
                        bob_central
                            .context
                            .conversation(&id)
                            .await
                            .unwrap()
                            .decrypt_message(renewed_proposal.proposal.to_bytes().unwrap())
                            .await
                            .unwrap();
                        assert_eq!(bob_central.pending_proposals(&id).await.len(), 1);
                        bob_central
                            .context
                            .conversation(&id)
                            .await
                            .unwrap()
                            .commit_pending_proposals()
                            .await
                            .unwrap();
                        let commit = bob_central.mls_transport.latest_commit().await;
                        let _decrypted = alice_central
                            .context
                            .conversation(&id)
                            .await
                            .unwrap()
                            .decrypt_message(commit.to_bytes().unwrap())
                            .await
                            .unwrap();
                        // Charlie is now in the group
                        assert!(
                            alice_central
                                .get_conversation_unchecked(&id)
                                .await
                                .members()
                                .contains_key::<Vec<u8>>(&charlie_central.get_client_id().await.to_vec())
                        );

                        // Bob also has Charlie in the group
                        assert!(
                            bob_central
                                .get_conversation_unchecked(&id)
                                .await
                                .members()
                                .contains_key::<Vec<u8>>(&charlie_central.get_client_id().await.to_vec())
                        );
                        assert!(alice_observer.has_changed().await);
                    })
                },
            )
            .await
        }

        #[apply(all_cred_cipher)]
        #[wasm_bindgen_test]
        pub async fn decrypting_a_commit_should_discard_pending_external_proposals(case: TestCase) {
            run_test_with_client_ids(
                case.clone(),
                ["alice", "bob", "charlie"],
                move |[mut alice_central, bob_central, charlie_central]| {
                    Box::pin(async move {
                        let id = conversation_id();
                        alice_central
                            .context
                            .new_conversation(&id, case.credential_type, case.cfg.clone())
                            .await
                            .unwrap();
                        alice_central.invite_all(&case, &id, [&bob_central]).await.unwrap();

                        // DS will create an external proposal to add Charlie
                        // But meanwhile Bob, before receiving the external proposal,
                        // will create a commit and send it to Alice.
                        // Alice will not renew the external proposal
                        let ext_proposal = charlie_central
                            .context
                            .new_external_add_proposal(
                                id.clone(),
                                alice_central.get_conversation_unchecked(&id).await.group.epoch(),
                                case.ciphersuite(),
                                case.credential_type,
                            )
                            .await
                            .unwrap();
                        assert!(alice_central.pending_proposals(&id).await.is_empty());
                        alice_central
                            .context
                            .conversation(&id)
                            .await
                            .unwrap()
                            .decrypt_message(ext_proposal.to_bytes().unwrap())
                            .await
                            .unwrap();
                        assert_eq!(alice_central.pending_proposals(&id).await.len(), 1);

                        bob_central
                            .context
                            .conversation(&id)
                            .await
                            .unwrap()
                            .update_key_material()
                            .await
                            .unwrap();
                        let commit = bob_central.mls_transport.latest_commit().await;
                        let alice_renewed_proposals = alice_central
                            .context
                            .conversation(&id)
                            .await
                            .unwrap()
                            .decrypt_message(commit.to_bytes().unwrap())
                            .await
                            .unwrap()
                            .proposals;
                        assert!(alice_renewed_proposals.is_empty());
                        assert!(alice_central.pending_proposals(&id).await.is_empty());
                    })
                },
            )
            .await
        }

        #[apply(all_cred_cipher)]
        #[wasm_bindgen_test]
        async fn should_not_return_sender_client_id(case: TestCase) {
            run_test_with_client_ids(case.clone(), ["alice", "bob"], move |[alice_central, bob_central]| {
                Box::pin(async move {
                    let id = conversation_id();
                    alice_central
                        .context
                        .new_conversation(&id, case.credential_type, case.cfg.clone())
                        .await
                        .unwrap();
                    alice_central.invite_all(&case, &id, [&bob_central]).await.unwrap();

                    alice_central
                        .context
                        .conversation(&id)
                        .await
                        .unwrap()
                        .update_key_material()
                        .await
                        .unwrap();
                    let commit = alice_central.mls_transport.latest_commit().await;

                    let sender_client_id = bob_central
                        .context
                        .conversation(&id)
                        .await
                        .unwrap()
                        .decrypt_message(commit.to_bytes().unwrap())
                        .await
                        .unwrap()
                        .sender_client_id;
                    assert!(sender_client_id.is_none());
                })
            })
            .await
        }
    }

    mod external_proposal {
        use super::*;

        #[apply(all_cred_cipher)]
        #[wasm_bindgen_test]
        async fn can_decrypt_external_proposal(case: TestCase) {
            run_test_with_client_ids(
                case.clone(),
                ["alice", "bob", "alice2"],
                move |[alice_central, bob_central, alice2_central]| {
                    Box::pin(async move {
                        let id = conversation_id();
                        alice_central
                            .context
                            .new_conversation(&id, case.credential_type, case.cfg.clone())
                            .await
                            .unwrap();
                        alice_central.invite_all(&case, &id, [&bob_central]).await.unwrap();

                        let bob_observer = TestEpochObserver::new();
                        bob_central
                            .client()
                            .await
                            .register_epoch_observer(bob_observer.clone())
                            .await
                            .unwrap();

                        let epoch = alice_central.get_conversation_unchecked(&id).await.group.epoch();
                        let ext_proposal = alice2_central
                            .context
                            .new_external_add_proposal(id.clone(), epoch, case.ciphersuite(), case.credential_type)
                            .await
                            .unwrap();

                        let decrypted = alice_central
                            .context
                            .conversation(&id)
                            .await
                            .unwrap()
                            .decrypt_message(&ext_proposal.to_bytes().unwrap())
                            .await
                            .unwrap();
                        assert!(decrypted.app_msg.is_none());
                        assert!(decrypted.delay.is_some());

                        let decrypted = bob_central
                            .context
                            .conversation(&id)
                            .await
                            .unwrap()
                            .decrypt_message(&ext_proposal.to_bytes().unwrap())
                            .await
                            .unwrap();
                        assert!(decrypted.app_msg.is_none());
                        assert!(decrypted.delay.is_some());
                        assert!(!bob_observer.has_changed().await)
                    })
                },
            )
            .await
        }
    }

    mod proposal {
        use super::*;

        // Ensures decrypting an proposal is durable
        #[apply(all_cred_cipher)]
        #[wasm_bindgen_test]
        async fn can_decrypt_proposal(case: TestCase) {
            run_test_with_client_ids(
                case.clone(),
                ["alice", "bob", "charlie"],
                move |[alice_central, bob_central, charlie_central]| {
                    Box::pin(async move {
                        let id = conversation_id();
                        alice_central
                            .context
                            .new_conversation(&id, case.credential_type, case.cfg.clone())
                            .await
                            .unwrap();
                        alice_central.invite_all(&case, &id, [&bob_central]).await.unwrap();

                        let charlie_kp = charlie_central.get_one_key_package(&case).await;
                        let proposal = alice_central
                            .context
                            .new_add_proposal(&id, charlie_kp)
                            .await
                            .unwrap()
                            .proposal;

                        let decrypted = bob_central
                            .context
                            .conversation(&id)
                            .await
                            .unwrap()
                            .decrypt_message(proposal.to_bytes().unwrap())
                            .await
                            .unwrap();

                        assert_eq!(bob_central.get_conversation_unchecked(&id).await.members().len(), 2);
                        // if 'decrypt_message' is not durable the commit won't contain the add proposal
                        bob_central
                            .context
                            .conversation(&id)
                            .await
                            .unwrap()
                            .commit_pending_proposals()
                            .await
                            .unwrap();
                        assert_eq!(bob_central.get_conversation_unchecked(&id).await.members().len(), 3);

                        alice_central.verify_sender_identity(&case, &decrypted).await;
                    })
                },
            )
            .await
        }

        #[apply(all_cred_cipher)]
        #[wasm_bindgen_test]
        async fn should_not_return_sender_client_id(case: TestCase) {
            run_test_with_client_ids(case.clone(), ["alice", "bob"], move |[alice_central, bob_central]| {
                Box::pin(async move {
                    let id = conversation_id();
                    alice_central
                        .context
                        .new_conversation(&id, case.credential_type, case.cfg.clone())
                        .await
                        .unwrap();
                    alice_central.invite_all(&case, &id, [&bob_central]).await.unwrap();

                    let proposal = alice_central.context.new_update_proposal(&id).await.unwrap().proposal;

                    let sender_client_id = bob_central
                        .context
                        .conversation(&id)
                        .await
                        .unwrap()
                        .decrypt_message(proposal.to_bytes().unwrap())
                        .await
                        .unwrap()
                        .sender_client_id;
                    assert!(sender_client_id.is_none());
                })
            })
            .await
        }
    }

    mod app_message {
        use super::*;

        #[apply(all_cred_cipher)]
        #[wasm_bindgen_test]
        async fn can_decrypt_app_message(case: TestCase) {
            run_test_with_client_ids(case.clone(), ["alice", "bob"], move |[alice_central, bob_central]| {
                Box::pin(async move {
                    let id = conversation_id();
                    alice_central
                        .context
                        .new_conversation(&id, case.credential_type, case.cfg.clone())
                        .await
                        .unwrap();
                    alice_central.invite_all(&case, &id, [&bob_central]).await.unwrap();

                    let alice_observer = TestEpochObserver::new();
                    alice_central
                        .client()
                        .await
                        .register_epoch_observer(alice_observer.clone())
                        .await
                        .unwrap();
                    let bob_observer = TestEpochObserver::new();
                    bob_central
                        .client()
                        .await
                        .register_epoch_observer(bob_observer.clone())
                        .await
                        .unwrap();

                    let msg = b"Hello bob";
                    let encrypted = alice_central
                        .context
                        .conversation(&id)
                        .await
                        .unwrap()
                        .encrypt_message(msg)
                        .await
                        .unwrap();
                    assert_ne!(&msg[..], &encrypted[..]);
                    let decrypted = bob_central
                        .context
                        .conversation(&id)
                        .await
                        .unwrap()
                        .decrypt_message(encrypted)
                        .await
                        .unwrap();
                    let dec_msg = decrypted.app_msg.as_ref().unwrap().as_slice();
                    assert_eq!(dec_msg, &msg[..]);
                    assert!(!bob_observer.has_changed().await);
                    alice_central.verify_sender_identity(&case, &decrypted).await;

                    let msg = b"Hello alice";
                    let encrypted = bob_central
                        .context
                        .conversation(&id)
                        .await
                        .unwrap()
                        .encrypt_message(msg)
                        .await
                        .unwrap();
                    assert_ne!(&msg[..], &encrypted[..]);
                    let decrypted = alice_central
                        .context
                        .conversation(&id)
                        .await
                        .unwrap()
                        .decrypt_message(encrypted)
                        .await
                        .unwrap();
                    let dec_msg = decrypted.app_msg.as_ref().unwrap().as_slice();
                    assert_eq!(dec_msg, &msg[..]);
                    assert!(!alice_observer.has_changed().await);
                    bob_central.verify_sender_identity(&case, &decrypted).await;
                })
            })
            .await
        }

        #[apply(all_cred_cipher)]
        #[wasm_bindgen_test]
        async fn cannot_decrypt_app_message_after_rejoining(case: TestCase) {
            run_test_with_client_ids(case.clone(), ["alice", "bob"], move |[alice_central, bob_central]| {
                Box::pin(async move {
                    let id = conversation_id();
                    alice_central
                        .context
                        .new_conversation(&id, case.credential_type, case.cfg.clone())
                        .await
                        .unwrap();
                    alice_central.invite_all(&case, &id, [&bob_central]).await.unwrap();

                    // encrypt a message in epoch 1
                    let msg = b"Hello bob";
                    let encrypted = alice_central
                        .context
                        .conversation(&id)
                        .await
                        .unwrap()
                        .encrypt_message(msg)
                        .await
                        .unwrap();

                    // Now Bob will rejoin the group and try to decrypt Alice's message
                    // in epoch 2 which should fail
                    let gi = alice_central.get_group_info(&id).await;
                    bob_central
                        .context
                        .join_by_external_commit(gi, case.custom_cfg(), case.credential_type)
                        .await
                        .unwrap();

                    // fails because of Forward Secrecy
                    let decrypt = bob_central
                        .context
                        .conversation(&id)
                        .await
                        .unwrap()
                        .decrypt_message(&encrypted)
                        .await;
                    assert!(matches!(decrypt.unwrap_err(), Error::DecryptionError));
                })
            })
            .await
        }

        #[apply(all_cred_cipher)]
        #[wasm_bindgen_test]
        async fn cannot_decrypt_app_message_from_future_epoch(case: TestCase) {
            run_test_with_client_ids(case.clone(), ["alice", "bob"], move |[alice_central, bob_central]| {
                Box::pin(async move {
                    let id = conversation_id();
                    alice_central
                        .context
                        .new_conversation(&id, case.credential_type, case.cfg.clone())
                        .await
                        .unwrap();
                    alice_central.invite_all(&case, &id, [&bob_central]).await.unwrap();

                    // only Alice will change epoch without notifying Bob
                    alice_central
                        .context
                        .conversation(&id)
                        .await
                        .unwrap()
                        .update_key_material()
                        .await
                        .unwrap();
                    let commit = alice_central.mls_transport.latest_commit().await;

                    // Now in epoch 2 Alice will encrypt a message
                    let msg = b"Hello bob";
                    let encrypted = alice_central
                        .context
                        .conversation(&id)
                        .await
                        .unwrap()
                        .encrypt_message(msg)
                        .await
                        .unwrap();

                    // which Bob cannot decrypt because of Post CompromiseSecurity
                    let decrypt = bob_central
                        .context
                        .conversation(&id)
                        .await
                        .unwrap()
                        .decrypt_message(&encrypted)
                        .await;
                    assert!(matches!(decrypt.unwrap_err(), Error::BufferedFutureMessage { .. }));

                    let decrypted_commit = bob_central
                        .context
                        .conversation(&id)
                        .await
                        .unwrap()
                        .decrypt_message(commit.to_bytes().unwrap())
                        .await
                        .unwrap();
                    let buffered_msg = decrypted_commit.buffered_messages.unwrap();
                    let decrypted_msg = buffered_msg.first().unwrap().app_msg.clone().unwrap();
                    assert_eq!(&decrypted_msg, msg);
                })
            })
            .await
        }

        #[apply(all_cred_cipher)]
        #[wasm_bindgen_test]
        async fn can_decrypt_app_message_in_any_order(mut case: TestCase) {
            // otherwise the test would fail because we decrypt messages in reverse order which is
            // kinda dropping them
            case.cfg.custom.maximum_forward_distance = 0;
            run_test_with_client_ids(case.clone(), ["alice", "bob"], move |[alice_central, bob_central]| {
                Box::pin(async move {
                    let id = conversation_id();
                    alice_central
                        .context
                        .new_conversation(&id, case.credential_type, case.cfg.clone())
                        .await
                        .unwrap();
                    alice_central.invite_all(&case, &id, [&bob_central]).await.unwrap();

                    let out_of_order_tolerance = case.custom_cfg().out_of_order_tolerance;
                    let nb_messages = out_of_order_tolerance * 2;
                    let mut messages = vec![];

                    // stack up encrypted messages..
                    for i in 0..nb_messages {
                        let msg = format!("Hello {i}");
                        let encrypted = alice_central
                            .context
                            .conversation(&id)
                            .await
                            .unwrap()
                            .encrypt_message(&msg)
                            .await
                            .unwrap();
                        messages.push((msg, encrypted));
                    }

                    // ..then unstack them to see out_of_order_tolerance come into play
                    messages.reverse();
                    for (i, (original, encrypted)) in messages.iter().enumerate() {
                        let decrypt = bob_central
                            .context
                            .conversation(&id)
                            .await
                            .unwrap()
                            .decrypt_message(encrypted)
                            .await;
                        if i > out_of_order_tolerance as usize {
                            let decrypted = decrypt.unwrap().app_msg.unwrap();
                            assert_eq!(decrypted, original.as_bytes());
                        } else {
                            assert!(matches!(decrypt.unwrap_err(), Error::DuplicateMessage))
                        }
                    }
                })
            })
            .await
        }

        #[apply(all_cred_cipher)]
        #[wasm_bindgen_test]
        async fn returns_sender_client_id(case: TestCase) {
            run_test_with_client_ids(case.clone(), ["alice", "bob"], move |[alice_central, bob_central]| {
                Box::pin(async move {
                    let id = conversation_id();
                    alice_central
                        .context
                        .new_conversation(&id, case.credential_type, case.cfg.clone())
                        .await
                        .unwrap();
                    alice_central.invite_all(&case, &id, [&bob_central]).await.unwrap();

                    let msg = b"Hello bob";
                    let encrypted = alice_central
                        .context
                        .conversation(&id)
                        .await
                        .unwrap()
                        .encrypt_message(msg)
                        .await
                        .unwrap();
                    assert_ne!(&msg[..], &encrypted[..]);

                    let sender_client_id = bob_central
                        .context
                        .conversation(&id)
                        .await
                        .unwrap()
                        .decrypt_message(encrypted)
                        .await
                        .unwrap()
                        .sender_client_id
                        .unwrap();
                    assert_eq!(sender_client_id, alice_central.get_client_id().await);
                })
            })
            .await
        }
    }

    mod epoch_sync {
        use super::*;

        #[apply(all_cred_cipher)]
        #[wasm_bindgen_test]
        async fn should_throw_specialized_error_when_epoch_too_old(mut case: TestCase) {
            case.cfg.custom.out_of_order_tolerance = 0;
            run_test_with_client_ids(case.clone(), ["alice", "bob"], move |[alice_central, bob_central]| {
                Box::pin(async move {
                    let id = conversation_id();
                    alice_central
                        .context
                        .new_conversation(&id, case.credential_type, case.cfg.clone())
                        .await
                        .unwrap();
                    alice_central.invite_all(&case, &id, [&bob_central]).await.unwrap();

                    // Alice encrypts a message to Bob
                    let bob_message1 = alice_central
                        .context
                        .conversation(&id)
                        .await
                        .unwrap()
                        .encrypt_message(b"Hello Bob")
                        .await
                        .unwrap();
                    let bob_message2 = alice_central
                        .context
                        .conversation(&id)
                        .await
                        .unwrap()
                        .encrypt_message(b"Hello again Bob")
                        .await
                        .unwrap();

                    // Move group's epoch forward by self updating
                    for _ in 0..MAX_PAST_EPOCHS {
                        alice_central
                            .context
                            .conversation(&id)
                            .await
                            .unwrap()
                            .update_key_material()
                            .await
                            .unwrap();
                        let commit = alice_central.mls_transport.latest_commit().await;
                        bob_central
                            .context
                            .conversation(&id)
                            .await
                            .unwrap()
                            .decrypt_message(commit.to_bytes().unwrap())
                            .await
                            .unwrap();
                    }
                    // Decrypt should work
                    let decrypt = bob_central
                        .context
                        .conversation(&id)
                        .await
                        .unwrap()
                        .decrypt_message(&bob_message1)
                        .await
                        .unwrap();
                    assert_eq!(decrypt.app_msg.unwrap(), b"Hello Bob");

                    // Moving the epochs once more should cause an error
                    alice_central
                        .context
                        .conversation(&id)
                        .await
                        .unwrap()
                        .update_key_material()
                        .await
                        .unwrap();
                    let commit = alice_central.mls_transport.latest_commit().await;
                    bob_central
                        .context
                        .conversation(&id)
                        .await
                        .unwrap()
                        .decrypt_message(commit.to_bytes().unwrap())
                        .await
                        .unwrap();

                    let decrypt = bob_central
                        .context
                        .conversation(&id)
                        .await
                        .unwrap()
                        .decrypt_message(&bob_message2)
                        .await;
                    assert!(matches!(decrypt.unwrap_err(), Error::MessageEpochTooOld));
                })
            })
            .await
        }

        #[apply(all_cred_cipher)]
        #[wasm_bindgen_test]
        async fn should_throw_specialized_error_when_epoch_desynchronized(mut case: TestCase) {
            case.cfg.custom.out_of_order_tolerance = 0;
            run_test_with_client_ids(case.clone(), ["alice", "bob"], move |[alice_central, bob_central]| {
                Box::pin(async move {
                    let id = conversation_id();
                    alice_central
                        .context
                        .new_conversation(&id, case.credential_type, case.cfg.clone())
                        .await
                        .unwrap();
                    alice_central.invite_all(&case, &id, [&bob_central]).await.unwrap();

                    // Alice generates a bunch of soon to be outdated messages
                    let old_proposal = alice_central
                        .context
                        .new_update_proposal(&id)
                        .await
                        .unwrap()
                        .proposal
                        .to_bytes()
                        .unwrap();
                    alice_central
                        .get_conversation_unchecked(&id)
                        .await
                        .group
                        .clear_pending_proposals();
                    let old_commit = alice_central
                        .create_unmerged_commit(&id)
                        .await
                        .commit
                        .to_bytes()
                        .unwrap();
                    alice_central
                        .context
                        .conversation(&id)
                        .await
                        .unwrap()
                        .clear_pending_commit()
                        .await
                        .unwrap();

                    // Now let's jump to next epoch
                    alice_central
                        .context
                        .conversation(&id)
                        .await
                        .unwrap()
                        .update_key_material()
                        .await
                        .unwrap();
                    let commit = alice_central.mls_transport.latest_commit().await;
                    bob_central
                        .context
                        .conversation(&id)
                        .await
                        .unwrap()
                        .decrypt_message(commit.to_bytes().unwrap())
                        .await
                        .unwrap();

                    // trying to consume outdated messages should fail with a dedicated error
                    let decrypt_err = bob_central
                        .context
                        .conversation(&id)
                        .await
                        .unwrap()
                        .decrypt_message(&old_proposal)
                        .await
                        .unwrap_err();

                    assert!(matches!(decrypt_err, Error::StaleProposal));

                    let decrypt_err = bob_central
                        .context
                        .conversation(&id)
                        .await
                        .unwrap()
                        .decrypt_message(&old_commit)
                        .await
                        .unwrap_err();

                    assert!(matches!(decrypt_err, Error::StaleCommit));
                })
            })
            .await
        }
    }
}
