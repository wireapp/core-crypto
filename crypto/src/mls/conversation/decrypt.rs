//! MLS defines 3 kind of messages: Proposal, Commits and Application messages. Since they can (should)
//! be all encrypted we need to first decrypt them before deciding what to do with them.
//!
//! This table summarizes when a MLS group can decrypt any message:
//!
//! | can decrypt ?     | 0 pend. Commit | 1 pend. Commit |
//! |-------------------|----------------|----------------|
//! | 0 pend. Proposal  | ✅              | ✅              |
//! | 1+ pend. Proposal | ✅              | ✅              |

use log::{debug, info};
use openmls::{
    framing::errors::{MessageDecryptionError, SecretTreeError},
    group::StagedCommit,
    prelude::{
        ContentType, CredentialType, MlsMessageIn, MlsMessageInBody, ProcessMessageError, ProcessedMessage,
        ProcessedMessageContent, Proposal, ProtocolMessage, StageCommitError, ValidationError,
    },
};
use openmls_traits::OpenMlsCryptoProvider;
use tls_codec::Deserialize;

use core_crypto_keystore::{
    connection::FetchFromDatabase,
    entities::{MlsBufferedCommit, MlsPendingMessage},
};
use mls_crypto_provider::MlsCryptoProvider;

use super::{Error, Result};
use crate::{
    KeystoreError, MlsError, RecursiveError,
    context::CentralContext,
    e2e_identity::{conversation_state::compute_state, init_certificates::NewCrlDistributionPoint},
    group_store::GroupStoreValue,
    mls::{
        ClientId, ConversationId, MlsConversation,
        client::Client,
        conversation::renew::Renew,
        credential::{
            crl::{
                extract_crl_uris_from_proposals, extract_crl_uris_from_update_path, get_new_crl_distribution_points,
            },
            ext::CredentialExt,
        },
    },
    obfuscate::Obfuscated,
    prelude::{E2eiConversationState, MlsProposalBundle, WireIdentity},
};

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
    pub has_epoch_changed: bool,
    /// see [MlsConversationDecryptMessage]
    pub identity: WireIdentity,
    /// see [MlsConversationDecryptMessage]
    pub crl_new_distribution_points: NewCrlDistributionPoint,
}

impl From<MlsConversationDecryptMessage> for MlsBufferedConversationDecryptMessage {
    fn from(from: MlsConversationDecryptMessage) -> Self {
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

/// Abstraction over a MLS group capable of decrypting a MLS message
impl MlsConversation {
    /// see [CentralContext::decrypt_message]
    #[allow(clippy::too_many_arguments)]
    #[cfg_attr(test, crate::durable)]
    // FIXME: this might be causing stack overflow. Retry when this is solved: https://github.com/tokio-rs/tracing/issues/1147. Tracking issue: WPB-9654
    // #[cfg_attr(not(test), tracing::instrument(err, skip_all))]
    pub async fn decrypt_message(
        &mut self,
        message: MlsMessageIn,
        parent_conv: Option<&GroupStoreValue<MlsConversation>>,
        client: &Client,
        backend: &MlsCryptoProvider,
        restore_pending: bool,
    ) -> Result<MlsConversationDecryptMessage> {
        let parsed_message = self.parse_message(backend, message.clone())?;

        let message_result = self.process_message(backend, parsed_message).await;

        // Handles the case where we receive our own commits.
        if let Err(Error::Mls(crate::MlsError {
            source:
                crate::MlsErrorKind::MlsMessageError(ProcessMessageError::InvalidCommit(StageCommitError::OwnCommit)),
            ..
        })) = message_result
        {
            let ct = self.extract_confirmation_tag_from_own_commit(&message)?;
            let mut decrypted_message = self.handle_own_commit(backend, ct).await?;
            // can't use `.then` because async
            debug_assert!(
                decrypted_message.buffered_messages.is_none(),
                "decrypted message should be constructed with empty buffer"
            );
            if restore_pending {
                decrypted_message.buffered_messages = self
                    .decrypt_and_clear_pending_messages(client, backend, parent_conv)
                    .await?;
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
                self.ciphersuite(),
                backend.authentication_service().borrow().await.as_ref(),
            )
            .map_err(RecursiveError::mls_credential("extracting identity"))?;

        let sender_client_id: ClientId = credential.credential.identity().into();

        let decrypted = match message.into_content() {
            ProcessedMessageContent::ApplicationMessage(app_msg) => {
                debug!(
                    group_id = Obfuscated::from(&self.id),
                    epoch = epoch.as_u64(),
                    sender_client_id = Obfuscated::from(&sender_client_id);
                    "Application message"
                );

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
                let crl_dps = extract_crl_uris_from_proposals(&[proposal.proposal().clone()])
                    .map_err(RecursiveError::mls_credential("extracting crl urls from proposals"))?;
                let crl_new_distribution_points = get_new_crl_distribution_points(backend, crl_dps)
                    .await
                    .map_err(RecursiveError::mls_credential("getting new crl distribution points"))?;

                info!(
                    group_id = Obfuscated::from(&self.id),
                    sender = Obfuscated::from(proposal.sender()),
                    proposals = Obfuscated::from(&proposal.proposal);
                    "Received proposal"
                );

                self.group.store_pending_proposal(*proposal);

                if let Some(commit) =
                    self.retrieve_buffered_commit(backend)
                        .await
                        .map_err(RecursiveError::mls_conversation(
                            "retrieving buffered commit while handling proposal",
                        ))?
                {
                    let process_result = self
                        .try_process_buffered_commit(commit, parent_conv, client, backend, restore_pending)
                        .await;

                    if process_result.is_ok() {
                        self.clear_buffered_commit(backend)
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

                MlsConversationDecryptMessage {
                    app_msg: None,
                    proposals: vec![],
                    is_active: true,
                    delay: self.compute_next_commit_delay(),
                    sender_client_id: None,
                    has_epoch_changed: false,
                    identity,
                    buffered_messages: None,
                    crl_new_distribution_points,
                }
            }
            ProcessedMessageContent::StagedCommitMessage(staged_commit) => {
                self.validate_commit(&staged_commit, backend).await?;

                let pending_proposals = self.self_pending_proposals().cloned().collect::<Vec<_>>();

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
                let pending_commit = self.group.pending_commit().cloned();

                self.group
                    .merge_staged_commit(backend, *staged_commit.clone())
                    .await
                    .map_err(MlsError::wrap("merge staged commit"))?;

                let (proposals_to_renew, needs_update) = Renew::renew(
                    &self.group.own_leaf_index(),
                    pending_proposals.into_iter(),
                    pending_commit.as_ref(),
                    staged_commit.as_ref(),
                );
                let proposals = self
                    .renew_proposals_for_current_epoch(client, backend, proposals_to_renew.into_iter(), needs_update)
                    .await?;

                // can't use `.then` because async
                let mut buffered_messages = None;
                if restore_pending {
                    buffered_messages = self
                        .decrypt_and_clear_pending_messages(client, backend, parent_conv)
                        .await?;
                }

                info!(
                    group_id = Obfuscated::from(&self.id),
                    epoch = staged_commit.staged_context().epoch().as_u64(),
                    proposals:? = staged_commit.queued_proposals().map(Obfuscated::from).collect::<Vec<_>>();
                    "Epoch advanced"
                );

                MlsConversationDecryptMessage {
                    app_msg: None,
                    proposals,
                    is_active: self.group.is_active(),
                    delay: self.compute_next_commit_delay(),
                    sender_client_id: None,
                    has_epoch_changed: true,
                    identity,
                    buffered_messages,
                    crl_new_distribution_points,
                }
            }
            ProcessedMessageContent::ExternalJoinProposalMessage(proposal) => {
                info!(
                    group_id = Obfuscated::from(&self.id),
                    sender = Obfuscated::from(proposal.sender());
                    "Received external join proposal"
                );

                let crl_dps = extract_crl_uris_from_proposals(&[proposal.proposal().clone()])
                    .map_err(RecursiveError::mls_credential("extracting crl uris from proposals"))?;
                let crl_new_distribution_points = get_new_crl_distribution_points(backend, crl_dps)
                    .await
                    .map_err(RecursiveError::mls_credential("getting new crl distribution points"))?;
                self.group.store_pending_proposal(*proposal);

                MlsConversationDecryptMessage {
                    app_msg: None,
                    proposals: vec![],
                    is_active: true,
                    delay: self.compute_next_commit_delay(),
                    sender_client_id: None,
                    has_epoch_changed: false,
                    identity,
                    buffered_messages: None,
                    crl_new_distribution_points,
                }
            }
        };

        self.persist_group_when_changed(&backend.keystore(), false).await?;

        Ok(decrypted)
    }

    /// Cache the bytes of a pending commit in the backend.
    ///
    /// By storing the raw commit bytes and doing deserialization/decryption from scratch, we preserve all
    /// security guarantees. When we do restore, it's as though the commit had simply been received later.
    async fn buffer_pending_commit(&self, backend: &MlsCryptoProvider, commit: impl AsRef<[u8]>) -> Result<()> {
        info!(group_id = Obfuscated::from(&self.id); "buffering pending commit");

        let pending_commit = MlsBufferedCommit::new(self.id.clone(), commit.as_ref().to_owned());

        backend
            .key_store()
            .save(pending_commit)
            .await
            .map_err(KeystoreError::wrap("buffering pending commit"))?;
        Ok(())
    }

    /// Retrieve the bytes of a pending commit.
    async fn retrieve_buffered_commit(&self, backend: &MlsCryptoProvider) -> Result<Option<Vec<u8>>> {
        info!(group_id = Obfuscated::from(&self.id); "attempting to retrieve pending commit");

        backend
            .keystore()
            .find::<MlsBufferedCommit>(&self.id)
            .await
            .map(|option| option.map(MlsBufferedCommit::into_commit_data))
            .map_err(KeystoreError::wrap("attempting to retrieve buffered commit"))
            .map_err(Into::into)
    }

    /// Try to apply a buffered commit.
    ///
    /// This is largely a convenience function which handles deserializing the message, and
    /// gives a convenient point around which we can add context to errors. However, it's also
    /// a place where we can introduce a pin, given that we're otherwise doing a recursive
    /// async call, which would result in an infinitely-sized future.
    async fn try_process_buffered_commit(
        &mut self,
        commit: impl AsRef<[u8]>,
        parent_conv: Option<&GroupStoreValue<MlsConversation>>,
        client: &Client,
        backend: &MlsCryptoProvider,
        restore_pending: bool,
    ) -> Result<MlsConversationDecryptMessage> {
        info!(group_id = Obfuscated::from(&self.id); "attempting to process pending commit");

        let message =
            MlsMessageIn::tls_deserialize(&mut commit.as_ref()).map_err(Error::tls_deserialize("mls message in"))?;

        Box::pin(self.decrypt_message(message, parent_conv, client, backend, restore_pending)).await
    }

    /// Remove the buffered commit for this conversation; it has been applied.
    async fn clear_buffered_commit(&self, backend: &MlsCryptoProvider) -> Result<()> {
        info!(group_id = Obfuscated::from(&self.id); "attempting to delete pending commit");

        backend
            .keystore()
            .remove::<MlsBufferedCommit, _>(&self.id)
            .await
            .map_err(KeystoreError::wrap("attempting to clear buffered commit"))
            .map_err(Into::into)
    }

    async fn decrypt_and_clear_pending_messages(
        &mut self,
        client: &Client,
        backend: &MlsCryptoProvider,
        parent_conv: Option<&GroupStoreValue<MlsConversation>>,
    ) -> Result<Option<Vec<MlsBufferedConversationDecryptMessage>>> {
        let pending_messages = self
            .restore_pending_messages(client, backend, parent_conv, false)
            .await?;

        if pending_messages.is_some() {
            info!(group_id = Obfuscated::from(&self.id); "Clearing all buffered messages for conversation");
            backend
                .key_store()
                .remove::<MlsPendingMessage, _>(self.id())
                .await
                .map_err(KeystoreError::wrap("removing MlsPendingMessage from keystore"))?;
        }

        Ok(pending_messages)
    }

    fn parse_message(&self, backend: &MlsCryptoProvider, msg_in: MlsMessageIn) -> Result<ParsedMessage> {
        let mut is_duplicate = false;
        let (protocol_message, content_type) = match msg_in.extract() {
            MlsMessageInBody::PublicMessage(m) => {
                is_duplicate = self.is_duplicate_message(backend, &m)?;
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
        backend: &MlsCryptoProvider,
        ParsedMessage {
            is_duplicate,
            protocol_message,
            content_type,
        }: ParsedMessage,
    ) -> Result<ProcessedMessage> {
        let msg_epoch = protocol_message.epoch().as_u64();
        let group_epoch = self.group.epoch().as_u64();
        let processed_msg = self
            .group
            .process_message(backend, protocol_message)
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

    async fn validate_commit(&self, commit: &StagedCommit, backend: &MlsCryptoProvider) -> Result<()> {
        if backend.authentication_service().is_env_setup().await {
            let credentials: Vec<_> = commit
                .add_proposals()
                .filter_map(|add_proposal| {
                    let credential = add_proposal.add_proposal().key_package().leaf_node().credential();

                    matches!(credential.credential_type(), CredentialType::X509).then(|| credential.clone())
                })
                .collect();
            let state = compute_state(
                self.ciphersuite(),
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

impl CentralContext {
    /// Deserializes a TLS-serialized message, then deciphers it
    ///
    /// # Arguments
    /// * `conversation` - the group/conversation id
    /// * `message` - the encrypted message as a byte array
    ///
    /// # Return type
    /// This method will return a tuple containing an optional message and an optional delay time
    /// for the callers to wait for committing. A message will be `None` in case the provided payload in
    /// case of a system message, such as Proposals and Commits. Otherwise it will return the message as a
    /// byte array. The delay will be `Some` when the message has a proposal
    ///
    /// # Errors
    /// If the conversation can't be found, an error will be returned. Other errors are originating
    /// from OpenMls and the KeyStore
    pub async fn decrypt_message(
        &self,
        id: &ConversationId,
        message: impl AsRef<[u8]>,
    ) -> Result<MlsConversationDecryptMessage> {
        let msg =
            MlsMessageIn::tls_deserialize(&mut message.as_ref()).map_err(Error::tls_deserialize("mls message in"))?;
        let Ok(conversation) = self.get_conversation(id).await else {
            return self
                .handle_when_group_is_pending(id, message)
                .await
                .map_err(RecursiveError::mls("handling when group is pending"))
                .map_err(Into::into);
        };
        let parent_conversation = self.get_parent_conversation(&conversation).await?;

        let client = &self
            .mls_client()
            .await
            .map_err(RecursiveError::root("getting mls client"))?;
        let backend = &self
            .mls_provider()
            .await
            .map_err(RecursiveError::root("getting mls provider"))?;

        let decrypt_message_result = conversation
            .write()
            .await
            .decrypt_message(msg, parent_conversation.as_ref(), client, backend, true)
            .await;

        if let Err(Error::BufferedFutureMessage { message_epoch }) = decrypt_message_result {
            self.handle_future_message(id, message.as_ref()).await?;
            info!(group_id = Obfuscated::from(id); "Buffered future message from epoch {message_epoch}");
        }

        // In the inner `decrypt_message` above, we raise the `BufferedCommit` error, but we only handle it here.
        // That's because in that scope we don't have access to the raw message bytes; here, we do.
        if let Err(Error::BufferedCommit) = decrypt_message_result {
            conversation
                .read()
                .await
                .buffer_pending_commit(backend, message)
                .await?;
        }

        let decrypt_message = decrypt_message_result?;

        if !decrypt_message.is_active {
            self.wipe_conversation(id).await?;
        }
        Ok(decrypt_message)
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
                        .conversation_guard(&id)
                        .await
                        .unwrap()
                        .update_key_material()
                        .await
                        .unwrap();
                    let commit = bob_central.mls_transport.latest_commit().await;
                    let MlsConversationDecryptMessage { is_active, .. } = alice_central
                        .context
                        .decrypt_message(&id, commit.to_bytes().unwrap())
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
                        .conversation_guard(&id)
                        .await
                        .unwrap()
                        .remove_members(&[alice_central.get_client_id().await])
                        .await
                        .unwrap();
                    let commit = bob_central.mls_transport.latest_commit().await;
                    let MlsConversationDecryptMessage { is_active, .. } = alice_central
                        .context
                        .decrypt_message(&id, commit.to_bytes().unwrap())
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

                    let epoch_before = alice_central.context.conversation_epoch(&id).await.unwrap();

                    alice_central
                        .context
                        .conversation_guard(&id)
                        .await
                        .unwrap()
                        .update_key_material()
                        .await
                        .unwrap();
                    let commit = alice_central.mls_transport.latest_commit().await;

                    let decrypted = bob_central
                        .context
                        .decrypt_message(&id, commit.to_bytes().unwrap())
                        .await
                        .unwrap();
                    let epoch_after = bob_central.context.conversation_epoch(&id).await.unwrap();
                    assert_eq!(epoch_after, epoch_before + 1);
                    assert!(decrypted.has_epoch_changed);
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

                        // Bob will create a proposal to add Charlie
                        // Alice will decrypt this proposal
                        // Then Bob will create a commit to update
                        // Alice will decrypt the commit but musn't renew the proposal to add Charlie
                        let charlie_kp = charlie_central.get_one_key_package(&case).await;

                        let add_charlie_proposal = bob_central.context.new_add_proposal(&id, charlie_kp).await.unwrap();
                        alice_central
                            .context
                            .decrypt_message(&id, add_charlie_proposal.proposal.to_bytes().unwrap())
                            .await
                            .unwrap();

                        bob_central
                            .context
                            .conversation_guard(&id)
                            .await
                            .unwrap()
                            .update_key_material()
                            .await
                            .unwrap();
                        let commit = bob_central.mls_transport.latest_commit().await;
                        let MlsConversationDecryptMessage {
                            proposals,
                            delay,
                            has_epoch_changed,
                            ..
                        } = alice_central
                            .context
                            .decrypt_message(&id, commit.to_bytes().unwrap())
                            .await
                            .unwrap();
                        assert!(proposals.is_empty());
                        assert!(delay.is_none());
                        assert!(alice_central.pending_proposals(&id).await.is_empty());
                        assert!(has_epoch_changed)
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

                        // Alice will create a proposal to add Charlie
                        // Bob will create a commit which Alice will decrypt
                        // Then Alice will renew her proposal
                        bob_central
                            .context
                            .conversation_guard(&id)
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
                            .decrypt_message(&id, bob_commit.to_bytes().unwrap())
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

                        // Let's use this proposal to see if it works
                        bob_central
                            .context
                            .decrypt_message(&id, renewed_proposal.proposal.to_bytes().unwrap())
                            .await
                            .unwrap();
                        assert_eq!(bob_central.pending_proposals(&id).await.len(), 1);
                        bob_central
                            .context
                            .conversation_guard(&id)
                            .await
                            .unwrap()
                            .commit_pending_proposals()
                            .await
                            .unwrap();
                        let commit = bob_central.mls_transport.latest_commit().await;
                        let decrypted = alice_central
                            .context
                            .decrypt_message(&id, commit.to_bytes().unwrap())
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
                        assert!(decrypted.has_epoch_changed);
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
                            .decrypt_message(&id, ext_proposal.to_bytes().unwrap())
                            .await
                            .unwrap();
                        assert_eq!(alice_central.pending_proposals(&id).await.len(), 1);

                        bob_central
                            .context
                            .conversation_guard(&id)
                            .await
                            .unwrap()
                            .update_key_material()
                            .await
                            .unwrap();
                        let commit = bob_central.mls_transport.latest_commit().await;
                        let alice_renewed_proposals = alice_central
                            .context
                            .decrypt_message(&id, commit.to_bytes().unwrap())
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
                        .conversation_guard(&id)
                        .await
                        .unwrap()
                        .update_key_material()
                        .await
                        .unwrap();
                    let commit = alice_central.mls_transport.latest_commit().await;

                    let sender_client_id = bob_central
                        .context
                        .decrypt_message(&id, commit.to_bytes().unwrap())
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

                        let epoch = alice_central.get_conversation_unchecked(&id).await.group.epoch();
                        let ext_proposal = alice2_central
                            .context
                            .new_external_add_proposal(id.clone(), epoch, case.ciphersuite(), case.credential_type)
                            .await
                            .unwrap();

                        let decrypted = alice_central
                            .context
                            .decrypt_message(&id, &ext_proposal.to_bytes().unwrap())
                            .await
                            .unwrap();
                        assert!(decrypted.app_msg.is_none());
                        assert!(decrypted.delay.is_some());

                        let decrypted = bob_central
                            .context
                            .decrypt_message(&id, &ext_proposal.to_bytes().unwrap())
                            .await
                            .unwrap();
                        assert!(decrypted.app_msg.is_none());
                        assert!(decrypted.delay.is_some());
                        assert!(!decrypted.has_epoch_changed)
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
                            .decrypt_message(&id, proposal.to_bytes().unwrap())
                            .await
                            .unwrap();

                        assert_eq!(bob_central.get_conversation_unchecked(&id).await.members().len(), 2);
                        // if 'decrypt_message' is not durable the commit won't contain the add proposal
                        bob_central
                            .context
                            .conversation_guard(&id)
                            .await
                            .unwrap()
                            .commit_pending_proposals()
                            .await
                            .unwrap();
                        assert_eq!(bob_central.get_conversation_unchecked(&id).await.members().len(), 3);
                        assert!(!decrypted.has_epoch_changed);

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
                        .decrypt_message(&id, proposal.to_bytes().unwrap())
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

                    let msg = b"Hello bob";
                    let encrypted = alice_central
                        .context
                        .conversation_guard(&id)
                        .await
                        .unwrap()
                        .encrypt_message(msg)
                        .await
                        .unwrap();
                    assert_ne!(&msg[..], &encrypted[..]);
                    let decrypted = bob_central.context.decrypt_message(&id, encrypted).await.unwrap();
                    let dec_msg = decrypted.app_msg.as_ref().unwrap().as_slice();
                    assert_eq!(dec_msg, &msg[..]);
                    assert!(!decrypted.has_epoch_changed);
                    alice_central.verify_sender_identity(&case, &decrypted).await;

                    let msg = b"Hello alice";
                    let encrypted = bob_central
                        .context
                        .conversation_guard(&id)
                        .await
                        .unwrap()
                        .encrypt_message(msg)
                        .await
                        .unwrap();
                    assert_ne!(&msg[..], &encrypted[..]);
                    let decrypted = alice_central.context.decrypt_message(&id, encrypted).await.unwrap();
                    let dec_msg = decrypted.app_msg.as_ref().unwrap().as_slice();
                    assert_eq!(dec_msg, &msg[..]);
                    assert!(!decrypted.has_epoch_changed);
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
                        .conversation_guard(&id)
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
                    let decrypt = bob_central.context.decrypt_message(&id, &encrypted).await;
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
                        .conversation_guard(&id)
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
                        .conversation_guard(&id)
                        .await
                        .unwrap()
                        .encrypt_message(msg)
                        .await
                        .unwrap();

                    // which Bob cannot decrypt because of Post CompromiseSecurity
                    let decrypt = bob_central.context.decrypt_message(&id, &encrypted).await;
                    assert!(matches!(decrypt.unwrap_err(), Error::BufferedFutureMessage { .. }));

                    let decrypted_commit = bob_central
                        .context
                        .decrypt_message(&id, commit.to_bytes().unwrap())
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
                            .conversation_guard(&id)
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
                        let decrypt = bob_central.context.decrypt_message(&id, encrypted).await;
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
                        .conversation_guard(&id)
                        .await
                        .unwrap()
                        .encrypt_message(msg)
                        .await
                        .unwrap();
                    assert_ne!(&msg[..], &encrypted[..]);

                    let sender_client_id = bob_central
                        .context
                        .decrypt_message(&id, encrypted)
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
                        .conversation_guard(&id)
                        .await
                        .unwrap()
                        .encrypt_message(b"Hello Bob")
                        .await
                        .unwrap();
                    let bob_message2 = alice_central
                        .context
                        .conversation_guard(&id)
                        .await
                        .unwrap()
                        .encrypt_message(b"Hello again Bob")
                        .await
                        .unwrap();

                    // Move group's epoch forward by self updating
                    for _ in 0..MAX_PAST_EPOCHS {
                        alice_central
                            .context
                            .conversation_guard(&id)
                            .await
                            .unwrap()
                            .update_key_material()
                            .await
                            .unwrap();
                        let commit = alice_central.mls_transport.latest_commit().await;
                        bob_central
                            .context
                            .decrypt_message(&id, commit.to_bytes().unwrap())
                            .await
                            .unwrap();
                    }
                    // Decrypt should work
                    let decrypt = bob_central.context.decrypt_message(&id, &bob_message1).await.unwrap();
                    assert_eq!(decrypt.app_msg.unwrap(), b"Hello Bob");

                    // Moving the epochs once more should cause an error
                    alice_central
                        .context
                        .conversation_guard(&id)
                        .await
                        .unwrap()
                        .update_key_material()
                        .await
                        .unwrap();
                    let commit = alice_central.mls_transport.latest_commit().await;
                    bob_central
                        .context
                        .decrypt_message(&id, commit.to_bytes().unwrap())
                        .await
                        .unwrap();

                    let decrypt = bob_central.context.decrypt_message(&id, &bob_message2).await;
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
                    alice_central.context.clear_pending_commit(&id).await.unwrap();

                    // Now let's jump to next epoch
                    alice_central
                        .context
                        .conversation_guard(&id)
                        .await
                        .unwrap()
                        .update_key_material()
                        .await
                        .unwrap();
                    let commit = alice_central.mls_transport.latest_commit().await;
                    bob_central
                        .context
                        .decrypt_message(&id, commit.to_bytes().unwrap())
                        .await
                        .unwrap();

                    // trying to consume outdated messages should fail with a dedicated error
                    let decrypt_err = bob_central
                        .context
                        .decrypt_message(&id, &old_proposal)
                        .await
                        .unwrap_err();

                    assert!(matches!(decrypt_err, Error::StaleProposal));

                    let decrypt_err = bob_central.context.decrypt_message(&id, &old_commit).await.unwrap_err();

                    assert!(matches!(decrypt_err, Error::StaleCommit));
                })
            })
            .await
        }
    }
}
