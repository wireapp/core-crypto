use super::{ConversationGuard, Result};
use crate::mls::conversation::renew::Renew;
use crate::mls::conversation::{ConversationWithMls, Error};
use crate::mls::credential::crl::{
    extract_crl_uris_from_proposals, extract_crl_uris_from_update_path, get_new_crl_distribution_points,
};
use crate::mls::credential::ext::CredentialExt as _;
use crate::obfuscate::Obfuscated;
use crate::prelude::{ClientId, MlsConversationDecryptMessage};
use crate::{MlsError, RecursiveError};
use log::{debug, info};
use openmls::framing::MlsMessageIn;
use openmls::prelude::{ProcessMessageError, ProcessedMessageContent, Proposal, StageCommitError};
use openmls_traits::OpenMlsCryptoProvider as _;
use tls_codec::Deserialize as _;

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
        let backend = &self.mls_provider().await?;
        let decrypt_message_result = self.decrypt_message_inner(mls_message_in, true).await;

        let conversation = self.conversation().await;
        let context = &self.central_context;
        if let Err(Error::BufferedFutureMessage { message_epoch }) = decrypt_message_result {
            context
                .handle_future_message(conversation.id(), message.as_ref())
                .await?;
            info!(group_id = Obfuscated::from(conversation.id()); "Buffered future message from epoch {message_epoch}");
        }

        // In the inner `decrypt_message` above, we raise the `BufferedCommit` error, but we only handle it here.
        // That's because in that scope we don't have access to the raw message bytes; here, we do.
        if let Err(Error::BufferedCommit) = decrypt_message_result {
            conversation.buffer_pending_commit(backend, message).await?;
        }

        let decrypt_message = decrypt_message_result?;

        if !decrypt_message.is_active {
            // drop conversation to allow borrowing `self` again
            drop(conversation);
            self.wipe().await?;
        }
        Ok(decrypt_message)
    }

    /// We need an inner part, because this may be called recursively.
    async fn decrypt_message_inner(
        &mut self,
        message: MlsMessageIn,
        keep_recursing: bool,
    ) -> Result<MlsConversationDecryptMessage> {
        let client = &self.mls_client().await?;
        let backend = &self.mls_provider().await?;
        let parent_conv = self.get_parent().await?;
        let parent_conv = parent_conv.as_ref();
        let mut conversation = self.conversation_mut().await;
        let parsed_message = conversation.parse_message(backend, message.clone())?;

        let message_result = conversation.process_message(backend, parsed_message).await;

        // Handles the case where we receive our own commits.
        if let Err(Error::Mls(crate::MlsError {
            source:
                crate::MlsErrorKind::MlsMessageError(ProcessMessageError::InvalidCommit(StageCommitError::OwnCommit)),
            ..
        })) = message_result
        {
            let ct = conversation.extract_confirmation_tag_from_own_commit(&message)?;
            let mut decrypted_message = conversation.handle_own_commit(backend, ct).await?;
            // can't use `.then` because async
            debug_assert!(
                decrypted_message.buffered_messages.is_none(),
                "decrypted message should be constructed with empty buffer"
            );
            if keep_recursing {
                decrypted_message.buffered_messages = conversation
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
                conversation.ciphersuite(),
                backend.authentication_service().borrow().await.as_ref(),
            )
            .map_err(RecursiveError::mls_credential("extracting identity"))?;

        let sender_client_id: ClientId = credential.credential.identity().into();

        let decrypted = match message.into_content() {
            ProcessedMessageContent::ApplicationMessage(app_msg) => {
                debug!(
                    group_id = Obfuscated::from(&conversation.id),
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
                    group_id = Obfuscated::from(&conversation.id),
                    sender = Obfuscated::from(proposal.sender()),
                    proposals = Obfuscated::from(&proposal.proposal);
                    "Received proposal"
                );

                conversation.group.store_pending_proposal(*proposal);

                if let Some(commit) =
                    conversation
                        .retrieve_buffered_commit(backend)
                        .await
                        .map_err(RecursiveError::mls_conversation(
                            "retrieving buffered commit while handling proposal",
                        ))?
                {
                    let process_result = conversation
                        .try_process_buffered_commit(commit, parent_conv, client, backend, keep_recursing)
                        .await;

                    if process_result.is_ok() {
                        conversation
                            .clear_buffered_commit(backend)
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
                    delay: conversation.compute_next_commit_delay(),
                    sender_client_id: None,
                    has_epoch_changed: false,
                    identity,
                    buffered_messages: None,
                    crl_new_distribution_points,
                }
            }
            ProcessedMessageContent::StagedCommitMessage(staged_commit) => {
                conversation.validate_commit(&staged_commit, backend).await?;

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
                if keep_recursing {
                    buffered_messages = conversation
                        .decrypt_and_clear_pending_messages(client, backend, parent_conv)
                        .await?;
                }

                info!(
                    group_id = Obfuscated::from(&conversation.id),
                    epoch = staged_commit.staged_context().epoch().as_u64(),
                    proposals:? = staged_commit.queued_proposals().map(Obfuscated::from).collect::<Vec<_>>();
                    "Epoch advanced"
                );

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

        conversation
            .persist_group_when_changed(&backend.keystore(), false)
            .await?;

        Ok(decrypted)
    }
}
