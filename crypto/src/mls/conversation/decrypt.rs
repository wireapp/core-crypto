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
use openmls::prelude::StageCommitError;
use openmls::{
    framing::errors::{MessageDecryptionError, SecretTreeError},
    group::StagedCommit,
    prelude::{
        ContentType, CredentialType, MlsMessageIn, MlsMessageInBody, ProcessMessageError, ProcessedMessage,
        ProcessedMessageContent, Proposal, ProtocolMessage, ValidationError,
    },
};
use openmls_traits::OpenMlsCryptoProvider;
use std::fmt::Debug;
use tls_codec::Deserialize;

use core_crypto_keystore::entities::MlsPendingMessage;
use mls_crypto_provider::MlsCryptoProvider;

use crate::context::CentralContext;
use crate::obfuscate::Obfuscated;
use crate::{
    e2e_identity::{conversation_state::compute_state, init_certificates::NewCrlDistributionPoint},
    group_store::GroupStoreValue,
    mls::{
        client::Client,
        conversation::renew::Renew,
        credential::{
            crl::{
                extract_crl_uris_from_proposals, extract_crl_uris_from_update_path, get_new_crl_distribution_points,
            },
            ext::CredentialExt,
        },
        ClientId, ConversationId, MlsConversation,
    },
    prelude::{E2eiConversationState, MlsProposalBundle, WireIdentity},
    CryptoError, CryptoResult, MlsError,
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
    ) -> CryptoResult<MlsConversationDecryptMessage> {
        let message = match self.parse_message(backend, message.clone()).await {
            // Handles the case where we receive our own commits.
            Err(CryptoError::MlsError(MlsError::MlsMessageError(ProcessMessageError::InvalidCommit(
                StageCommitError::OwnCommit,
            )))) => {
                let ct = self.extract_confirmation_tag_from_own_commit(&message)?;
                return self.handle_own_commit(backend, ct).await;
            }
            Ok(processed_message) => Ok(processed_message),
            Err(e) => Err(e),
        }?;

        let credential = message.credential();
        let epoch = message.epoch();

        let identity = credential.extract_identity(
            self.ciphersuite(),
            backend.authentication_service().borrow().await.as_ref(),
        )?;

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
                let crl_dps = extract_crl_uris_from_proposals(&[proposal.proposal().clone()])?;
                let crl_new_distribution_points = get_new_crl_distribution_points(backend, crl_dps).await?;

                info!(
                    group_id = Obfuscated::from(&self.id),
                    sender = Obfuscated::from(proposal.sender()),
                    proposals = Obfuscated::from(&proposal.proposal);
                    "Received proposal"
                );

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
            ProcessedMessageContent::StagedCommitMessage(staged_commit) => {
                self.validate_commit(&staged_commit, backend).await?;

                #[allow(clippy::needless_collect)] // false positive
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
                let mut crl_dps = extract_crl_uris_from_proposals(&proposal_refs)?;
                crl_dps.extend(extract_crl_uris_from_update_path(&staged_commit)?);

                let crl_new_distribution_points = get_new_crl_distribution_points(backend, crl_dps).await?;

                // getting the pending has to be done before `merge_staged_commit` otherwise it's wiped out
                let pending_commit = self.group.pending_commit().cloned();

                self.group
                    .merge_staged_commit(backend, *staged_commit.clone())
                    .await
                    .map_err(MlsError::from)?;

                let (proposals_to_renew, needs_update) = Renew::renew(
                    &self.group.own_leaf_index(),
                    pending_proposals.into_iter(),
                    pending_commit.as_ref(),
                    staged_commit.as_ref(),
                );
                let proposals = self
                    .renew_proposals_for_current_epoch(client, backend, proposals_to_renew.into_iter(), needs_update)
                    .await?;

                let buffered_messages = if restore_pending {
                    if let Some(pm) = self
                        .restore_pending_messages(client, backend, parent_conv, false)
                        .await?
                    {
                        backend.key_store().remove::<MlsPendingMessage, _>(self.id()).await?;
                        Some(pm)
                    } else {
                        None
                    }
                } else {
                    None
                };

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

                let crl_dps = extract_crl_uris_from_proposals(&[proposal.proposal().clone()])?;
                let crl_new_distribution_points = get_new_crl_distribution_points(backend, crl_dps).await?;
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

    async fn parse_message(
        &mut self,
        backend: &MlsCryptoProvider,
        msg_in: MlsMessageIn,
    ) -> CryptoResult<ProcessedMessage> {
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
                return Err(CryptoError::MlsError(
                    ProcessMessageError::IncompatibleWireFormat.into(),
                ))
            }
        };
        let msg_epoch = protocol_message.epoch().as_u64();
        let group_epoch = self.group.epoch().as_u64();
        let processed_msg = self
            .group
            .process_message(backend, protocol_message)
            .await
            .map_err(|e| match e {
                ProcessMessageError::ValidationError(ValidationError::UnableToDecrypt(
                    MessageDecryptionError::GenerationOutOfBound,
                )) => CryptoError::DuplicateMessage,
                ProcessMessageError::ValidationError(ValidationError::WrongEpoch) => {
                    if is_duplicate {
                        CryptoError::DuplicateMessage
                    } else if msg_epoch == group_epoch + 1 {
                        // limit to next epoch otherwise if we were buffering a commit for epoch + 2
                        // we would fail when trying to decrypt it in [MlsCentral::commit_accepted]
                        CryptoError::BufferedFutureMessage
                    } else if msg_epoch < group_epoch {
                        match content_type {
                            ContentType::Application => CryptoError::StaleMessage,
                            ContentType::Commit => CryptoError::StaleCommit,
                            ContentType::Proposal => CryptoError::StaleProposal,
                        }
                    } else {
                        CryptoError::WrongEpoch
                    }
                }
                ProcessMessageError::ValidationError(ValidationError::UnableToDecrypt(
                    MessageDecryptionError::AeadError,
                )) => CryptoError::DecryptionError,
                ProcessMessageError::ValidationError(ValidationError::UnableToDecrypt(
                    MessageDecryptionError::SecretTreeError(SecretTreeError::TooDistantInThePast),
                )) => CryptoError::MessageEpochTooOld,
                _ => CryptoError::from(MlsError::from(e)),
            })?;
        if is_duplicate {
            return Err(CryptoError::DuplicateMessage);
        }
        Ok(processed_msg)
    }

    async fn validate_commit(&self, commit: &StagedCommit, backend: &MlsCryptoProvider) -> CryptoResult<()> {
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
                // return Err(CryptoError::InvalidCertificateChain);
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
    ) -> CryptoResult<MlsConversationDecryptMessage> {
        let msg = MlsMessageIn::tls_deserialize(&mut message.as_ref()).map_err(MlsError::from)?;
        let Ok(conversation) = self.get_conversation(id).await else {
            return self.handle_when_group_is_pending(id, message).await;
        };
        let parent_conversation = self.get_parent_conversation(&conversation).await?;
        let client = &self.mls_client().await?;
        let decrypt_message = conversation
            .write()
            .await
            .decrypt_message(
                msg,
                parent_conversation.as_ref(),
                client,
                &self.mls_provider().await?,
                true,
            )
            .await;

        let decrypt_message = match decrypt_message {
            Err(CryptoError::BufferedFutureMessage) => self.handle_future_message(id, message).await?,
            _ => decrypt_message?,
        };

        if !decrypt_message.is_active {
            self.wipe_conversation(id).await?;
        }
        Ok(decrypt_message)
    }
}

#[cfg(test)]
mod tests {
    use wasm_bindgen_test::*;

    use crate::{mls::conversation::config::MAX_PAST_EPOCHS, prelude::MlsCommitBundle, test_utils::*, CryptoError};

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

                    let MlsCommitBundle { commit, .. } = bob_central.context.update_keying_material(&id).await.unwrap();
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

                    let MlsCommitBundle { commit, .. } = bob_central
                        .context
                        .remove_members_from_conversation(&id, &[alice_central.get_client_id().await])
                        .await
                        .unwrap();
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

                    let MlsCommitBundle { commit, .. } =
                        alice_central.context.update_keying_material(&id).await.unwrap();
                    alice_central.context.commit_accepted(&id).await.unwrap();

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
        pub async fn decrypting_a_commit_should_clear_pending_commit(case: TestCase) {
            run_test_with_client_ids(
                case.clone(),
                ["alice", "bob", "charlie", "debbie"],
                move |[alice_central, bob_central, charlie_central, debbie_central]| {
                    Box::pin(async move {
                        let id = conversation_id();
                        alice_central
                            .context
                            .new_conversation(&id, case.credential_type, case.cfg.clone())
                            .await
                            .unwrap();
                        alice_central.invite_all(&case, &id, [&bob_central]).await.unwrap();

                        // Alice creates a commit which will be superseded by Bob's one
                        let charlie = charlie_central.rand_key_package(&case).await;
                        let debbie = debbie_central.rand_key_package(&case).await;
                        alice_central
                            .context
                            .add_members_to_conversation(&id, vec![charlie.clone()])
                            .await
                            .unwrap();
                        assert!(alice_central.pending_commit(&id).await.is_some());

                        let add_debbie_commit = bob_central
                            .context
                            .add_members_to_conversation(&id, vec![debbie.clone()])
                            .await
                            .unwrap()
                            .commit;
                        let decrypted = alice_central
                            .context
                            .decrypt_message(&id, add_debbie_commit.to_bytes().unwrap())
                            .await
                            .unwrap();
                        // Now Debbie should be in members and not Charlie
                        let members = alice_central.get_conversation_unchecked(&id).await.members();

                        let dc = debbie.unverified_credential();
                        let debbie_id = dc.credential.identity();
                        assert!(members.get(debbie_id).is_some());

                        let cc = charlie.unverified_credential();
                        let charlie_id = cc.credential.identity();
                        assert!(members.get(charlie_id).is_none());

                        // Previous commit to add Charlie has been discarded but its proposals will be renewed
                        assert!(alice_central.pending_commit(&id).await.is_none());
                        assert!(decrypted.has_epoch_changed)
                    })
                },
            )
            .await
        }

        #[apply(all_cred_cipher)]
        #[wasm_bindgen_test]
        pub async fn decrypting_a_commit_should_renew_proposals_in_pending_commit(case: TestCase) {
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

                        // Alice will create a commit to add Charlie
                        // Bob will create a commit which will be accepted first by DS so Alice will decrypt it
                        // Then Alice will renew the proposal in her pending commit
                        let charlie = charlie_central.rand_key_package(&case).await;

                        let bob_commit = bob_central.context.update_keying_material(&id).await.unwrap().commit;
                        bob_central.context.commit_accepted(&id).await.unwrap();

                        // Alice propose to add Charlie
                        alice_central
                            .context
                            .add_members_to_conversation(&id, vec![charlie.clone()])
                            .await
                            .unwrap();
                        assert!(alice_central.pending_commit(&id).await.is_some());

                        // But first she receives Bob commit
                        let MlsConversationDecryptMessage { proposals, delay, .. } = alice_central
                            .context
                            .decrypt_message(&id, bob_commit.to_bytes().unwrap())
                            .await
                            .unwrap();
                        // So Charlie has not been added to the group
                        let cc = charlie.unverified_credential();
                        let charlie_id = cc.credential.identity();
                        assert!(alice_central
                            .get_conversation_unchecked(&id)
                            .await
                            .members()
                            .get(charlie_id)
                            .is_none());
                        // Make sure we are suggesting a commit delay
                        assert!(delay.is_some());

                        // But its proposal to add Charlie has been renewed and is also in store
                        assert!(!proposals.is_empty());
                        assert_eq!(alice_central.pending_proposals(&id).await.len(), 1);
                        assert!(alice_central.pending_commit(&id).await.is_none());

                        // Let's commit this proposal to see if it works
                        for p in proposals {
                            // But first, proposals have to be fan out to Bob
                            bob_central
                                .context
                                .decrypt_message(&id, p.proposal.to_bytes().unwrap())
                                .await
                                .unwrap();
                        }

                        let MlsCommitBundle { commit, welcome, .. } = alice_central
                            .context
                            .commit_pending_proposals(&id)
                            .await
                            .unwrap()
                            .unwrap();
                        alice_central.context.commit_accepted(&id).await.unwrap();
                        // Charlie is now in the group
                        assert!(alice_central
                            .get_conversation_unchecked(&id)
                            .await
                            .members()
                            .get(charlie_id)
                            .is_some());

                        let decrypted = bob_central
                            .context
                            .decrypt_message(&id, commit.to_bytes().unwrap())
                            .await
                            .unwrap();
                        // Bob also has Charlie in the group
                        let cc = charlie.unverified_credential();
                        let charlie_id = cc.credential.identity();
                        assert!(bob_central
                            .get_conversation_unchecked(&id)
                            .await
                            .members()
                            .get(charlie_id)
                            .is_some());
                        assert!(decrypted.has_epoch_changed);

                        // Charlie can join with the Welcome from renewed Add proposal
                        let id = charlie_central
                            .context
                            .process_welcome_message(welcome.unwrap().into(), case.custom_cfg())
                            .await
                            .unwrap()
                            .id;
                        assert!(charlie_central.try_talk_to(&id, &alice_central).await.is_ok());
                    })
                },
            )
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

                        let MlsCommitBundle { commit, .. } =
                            bob_central.context.update_keying_material(&id).await.unwrap();
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
                        let bob_commit = bob_central.context.update_keying_material(&id).await.unwrap().commit;
                        bob_central.context.commit_accepted(&id).await.unwrap();
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
                        assert!(alice_central
                            .get_conversation_unchecked(&id)
                            .await
                            .members()
                            .get(&b"charlie".to_vec())
                            .is_none());
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
                        let MlsCommitBundle { commit, .. } = bob_central
                            .context
                            .commit_pending_proposals(&id)
                            .await
                            .unwrap()
                            .unwrap();
                        let decrypted = alice_central
                            .context
                            .decrypt_message(&id, commit.to_bytes().unwrap())
                            .await
                            .unwrap();
                        // Charlie is now in the group
                        assert!(alice_central
                            .get_conversation_unchecked(&id)
                            .await
                            .members()
                            .get::<Vec<u8>>(&charlie_central.get_client_id().await.to_vec())
                            .is_some());

                        // Bob also has Charlie in the group
                        bob_central.context.commit_accepted(&id).await.unwrap();
                        assert!(bob_central
                            .get_conversation_unchecked(&id)
                            .await
                            .members()
                            .get::<Vec<u8>>(&charlie_central.get_client_id().await.to_vec())
                            .is_some());
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

                        let MlsCommitBundle { commit, .. } =
                            bob_central.context.update_keying_material(&id).await.unwrap();
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

                    let commit = alice_central.context.update_keying_material(&id).await.unwrap().commit;

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
                            .commit_pending_proposals(&id)
                            .await
                            .unwrap()
                            .unwrap();
                        bob_central.context.commit_accepted(&id).await.unwrap();
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
                    let encrypted = alice_central.context.encrypt_message(&id, msg).await.unwrap();
                    assert_ne!(&msg[..], &encrypted[..]);
                    let decrypted = bob_central.context.decrypt_message(&id, encrypted).await.unwrap();
                    let dec_msg = decrypted.app_msg.as_ref().unwrap().as_slice();
                    assert_eq!(dec_msg, &msg[..]);
                    assert!(!decrypted.has_epoch_changed);
                    alice_central.verify_sender_identity(&case, &decrypted).await;

                    let msg = b"Hello alice";
                    let encrypted = bob_central.context.encrypt_message(&id, msg).await.unwrap();
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
                    let encrypted = alice_central.context.encrypt_message(&id, msg).await.unwrap();

                    // Now Bob will rejoin the group and try to decrypt Alice's message
                    // in epoch 2 which should fail
                    let gi = alice_central.get_group_info(&id).await;
                    bob_central
                        .context
                        .join_by_external_commit(gi, case.custom_cfg(), case.credential_type)
                        .await
                        .unwrap();
                    bob_central
                        .context
                        .merge_pending_group_from_external_commit(&id)
                        .await
                        .unwrap();

                    // fails because of Forward Secrecy
                    let decrypt = bob_central.context.decrypt_message(&id, &encrypted).await;
                    assert!(matches!(decrypt.unwrap_err(), CryptoError::DecryptionError));
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
                    let commit = alice_central.context.update_keying_material(&id).await.unwrap().commit;
                    alice_central.context.commit_accepted(&id).await.unwrap();

                    // Now in epoch 2 Alice will encrypt a message
                    let msg = b"Hello bob";
                    let encrypted = alice_central.context.encrypt_message(&id, msg).await.unwrap();

                    // which Bob cannot decrypt because of Post CompromiseSecurity
                    let decrypt = bob_central.context.decrypt_message(&id, &encrypted).await;
                    assert!(matches!(decrypt.unwrap_err(), CryptoError::BufferedFutureMessage));

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
                        let encrypted = alice_central.context.encrypt_message(&id, &msg).await.unwrap();
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
                            assert!(matches!(decrypt.unwrap_err(), CryptoError::DuplicateMessage))
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
                    let encrypted = alice_central.context.encrypt_message(&id, msg).await.unwrap();
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
                    let bob_message1 = alice_central.context.encrypt_message(&id, b"Hello Bob").await.unwrap();
                    let bob_message2 = alice_central
                        .context
                        .encrypt_message(&id, b"Hello again Bob")
                        .await
                        .unwrap();

                    // Move group's epoch forward by self updating
                    for _ in 0..MAX_PAST_EPOCHS {
                        let commit = alice_central.context.update_keying_material(&id).await.unwrap().commit;
                        alice_central.context.commit_accepted(&id).await.unwrap();
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
                    let commit = alice_central.context.update_keying_material(&id).await.unwrap().commit;
                    alice_central.context.commit_accepted(&id).await.unwrap();
                    bob_central
                        .context
                        .decrypt_message(&id, commit.to_bytes().unwrap())
                        .await
                        .unwrap();

                    let decrypt = bob_central.context.decrypt_message(&id, &bob_message2).await;
                    assert!(matches!(decrypt.unwrap_err(), CryptoError::MessageEpochTooOld));
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
                        .context
                        .update_keying_material(&id)
                        .await
                        .unwrap()
                        .commit
                        .to_bytes()
                        .unwrap();
                    alice_central.context.clear_pending_commit(&id).await.unwrap();

                    // Now let's jump to next epoch
                    let commit = alice_central.context.update_keying_material(&id).await.unwrap().commit;
                    alice_central.context.commit_accepted(&id).await.unwrap();
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

                    assert!(matches!(decrypt_err, CryptoError::StaleProposal));

                    let decrypt_err = bob_central.context.decrypt_message(&id, &old_commit).await.unwrap_err();

                    assert!(matches!(decrypt_err, CryptoError::StaleCommit));
                })
            })
            .await
        }
    }
}
