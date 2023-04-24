//! MLS defines 3 kind of messages: Proposal, Commits and Application messages. Since they can (should)
//! be all encrypted we need to first decrypt them before deciding what to do with them.
//!
//! This table summarizes when a MLS group can decrypt any message:
//!
//! | can decrypt ?     | 0 pend. Commit | 1 pend. Commit |
//! |-------------------|----------------|----------------|
//! | 0 pend. Proposal  | ✅              | ✅              |
//! | 1+ pend. Proposal | ✅              | ✅              |

use openmls::{
    framing::errors::{MessageDecryptionError, SecretTreeError},
    prelude::{
        MlsMessageIn, MlsMessageInBody, ProcessMessageError, ProcessedMessage, ProcessedMessageContent,
        ProtocolMessage, ValidationError,
    },
};

use mls_crypto_provider::MlsCryptoProvider;
use tls_codec::Deserialize;

use crate::{
    group_store::GroupStoreValue,
    mls::{client::Client, conversation::renew::Renew, ClientId, ConversationId, MlsCentral, MlsConversation},
    prelude::{MlsProposalBundle, WireIdentity},
    CoreCryptoCallbacks, CryptoError, CryptoResult, MlsError,
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
    /// Is the conversation still active after receiving this commit
    /// aka has the user been removed from the group
    pub is_active: bool,
    /// delay time in seconds to feed caller timer for committing
    pub delay: Option<u64>,
    /// [ClientId] of the sender of the message being decrypted. Only present for application messages.
    pub sender_client_id: Option<ClientId>,
    /// Is the epoch changed after decrypting this message
    pub has_epoch_changed: bool,
    /// Identity claims present in the sender credential
    /// Only present when the credential is a x509 certificate
    /// Present for all messages
    pub identity: Option<WireIdentity>,
}

/// Abstraction over a MLS group capable of decrypting a MLS message
impl MlsConversation {
    /// see [MlsCentral::decrypt_message]
    #[cfg_attr(test, crate::durable)]
    pub async fn decrypt_message(
        &mut self,
        message: impl AsRef<[u8]>,
        parent_conversation: Option<GroupStoreValue<MlsConversation>>,
        client: &Client,
        backend: &MlsCryptoProvider,
        callbacks: Option<&dyn CoreCryptoCallbacks>,
    ) -> CryptoResult<MlsConversationDecryptMessage> {
        let msg_in = openmls::framing::MlsMessageIn::tls_deserialize_bytes(message.as_ref()).map_err(MlsError::from)?;

        let message = self.parse_message(backend, msg_in).await?;

        let msg_epoch = message.epoch();

        let credential = message.credential();
        let identity = Self::extract_identity(credential)?;

        let sender_client_id = credential.identity().into();

        let decrypted = match message.into_content() {
            ProcessedMessageContent::ApplicationMessage(app_msg) => {
                if msg_epoch.as_u64() < self.group.epoch().as_u64() {
                    return Err(CryptoError::WrongEpoch);
                }

                MlsConversationDecryptMessage {
                    app_msg: Some(app_msg.into_bytes()),
                    proposals: vec![],
                    is_active: true,
                    delay: None,
                    sender_client_id: Some(sender_client_id),
                    has_epoch_changed: false,
                    identity,
                }
            }
            ProcessedMessageContent::ProposalMessage(proposal) => {
                self.group.store_pending_proposal(*proposal);
                MlsConversationDecryptMessage {
                    app_msg: None,
                    proposals: vec![],
                    is_active: true,
                    delay: self.compute_next_commit_delay(),
                    sender_client_id: None,
                    has_epoch_changed: false,
                    identity,
                }
            }
            ProcessedMessageContent::StagedCommitMessage(staged_commit) => {
                self.validate_external_commit(&staged_commit, sender_client_id, parent_conversation, callbacks)
                    .await?;

                #[allow(clippy::needless_collect)] // false positive
                let pending_proposals = self.self_pending_proposals().cloned().collect::<Vec<_>>();

                // getting the pending has to be done before `merge_staged_commit` otherwise it's wiped out
                let pending_commit = self.group.pending_commit().cloned();

                self.group
                    .merge_staged_commit(backend, *staged_commit.clone())
                    .await
                    .map_err(MlsError::from)?;

                let (proposals, update_self) = Renew::renew(
                    Some(self.group.own_leaf_index()),
                    pending_proposals.into_iter(),
                    pending_commit.as_ref(),
                    staged_commit.as_ref(),
                );
                let proposals = self
                    .renew_proposals_for_current_epoch(client, backend, proposals.into_iter(), update_self)
                    .await?;

                MlsConversationDecryptMessage {
                    app_msg: None,
                    proposals,
                    is_active: self.group.is_active(),
                    delay: self.compute_next_commit_delay(),
                    sender_client_id: None,
                    has_epoch_changed: true,
                    identity,
                }
            }
            ProcessedMessageContent::ExternalJoinProposalMessage(proposal) => {
                self.validate_external_proposal(&proposal, parent_conversation, callbacks)
                    .await?;
                self.group.store_pending_proposal(*proposal);

                MlsConversationDecryptMessage {
                    app_msg: None,
                    proposals: vec![],
                    is_active: true,
                    delay: self.compute_next_commit_delay(),
                    sender_client_id: None,
                    has_epoch_changed: false,
                    identity,
                }
            }
        };

        self.persist_group_when_changed(backend, false).await?;

        Ok(decrypted)
    }

    async fn parse_message(
        &mut self,
        backend: &MlsCryptoProvider,
        msg_in: MlsMessageIn,
    ) -> CryptoResult<ProcessedMessage> {
        let protocol_message = match msg_in.extract() {
            MlsMessageInBody::PublicMessage(m) => ProtocolMessage::PublicMessage(m),
            MlsMessageInBody::PrivateMessage(m) => ProtocolMessage::PrivateMessage(m),
            _ => {
                return Err(CryptoError::MlsError(
                    ProcessMessageError::IncompatibleWireFormat.into(),
                ))
            }
        };
        self.group
            .process_message(backend, protocol_message)
            .await
            .map_err(|e| match e {
                ProcessMessageError::ValidationError(ValidationError::UnableToDecrypt(
                    MessageDecryptionError::GenerationOutOfBound,
                )) => CryptoError::GenerationOutOfBound,
                ProcessMessageError::ValidationError(ValidationError::WrongEpoch) => CryptoError::WrongEpoch,
                ProcessMessageError::ValidationError(ValidationError::UnableToDecrypt(
                    MessageDecryptionError::AeadError,
                )) => CryptoError::DecryptionError,
                ProcessMessageError::ValidationError(ValidationError::UnableToDecrypt(
                    MessageDecryptionError::SecretTreeError(SecretTreeError::TooDistantInThePast),
                )) => CryptoError::MessageEpochTooOld,
                _ => CryptoError::from(MlsError::from(e)),
            })
    }
}

impl MlsCentral {
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
        &mut self,
        conversation_id: &ConversationId,
        message: impl AsRef<[u8]>,
    ) -> CryptoResult<MlsConversationDecryptMessage> {
        let parent_conversation = self.get_parent_conversation(conversation_id).await?;
        let decrypt_message = self
            .get_conversation(conversation_id)
            .await?
            .write()
            .await
            .decrypt_message(
                message.as_ref(),
                parent_conversation,
                self.mls_client()?,
                &self.mls_backend,
                self.callbacks.as_ref().map(|boxed| boxed.as_ref()),
            )
            .await?;

        if !decrypt_message.is_active {
            self.wipe_conversation(conversation_id).await?;
        }
        Ok(decrypt_message)
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::{
        prelude::{handshake::MlsCommitBundle, MemberId, MlsProposal, MlsWirePolicy},
        test_utils::{ValidationCallbacks, *},
        CryptoError,
    };
    use openmls::prelude::KeyPackageRef;
    use std::time::Duration;
    use wasm_bindgen_test::*;

    wasm_bindgen_test_configure!(run_in_browser);

    pub mod is_active {
        use super::*;

        #[apply(all_cred_cipher)]
        #[wasm_bindgen_test]
        pub async fn decrypting_a_regular_commit_should_leave_conversation_active(case: TestCase) {
            run_test_with_client_ids(
                case.clone(),
                ["alice", "bob"],
                move |[mut alice_central, mut bob_central]| {
                    Box::pin(async move {
                        let id = conversation_id();
                        alice_central
                            .new_conversation(id.clone(), case.credential_type, case.cfg.clone())
                            .await
                            .unwrap();
                        alice_central
                            .invite(&id, &mut bob_central, case.custom_cfg())
                            .await
                            .unwrap();

                        let MlsCommitBundle { commit, .. } = bob_central.update_keying_material(&id).await.unwrap();
                        let MlsConversationDecryptMessage { is_active, .. } = alice_central
                            .decrypt_message(&id, commit.to_bytes().unwrap())
                            .await
                            .unwrap();
                        assert!(is_active)
                    })
                },
            )
            .await
        }

        #[apply(all_cred_cipher)]
        #[wasm_bindgen_test]
        pub async fn decrypting_a_commit_removing_self_should_set_conversation_inactive(case: TestCase) {
            run_test_with_client_ids(
                case.clone(),
                ["alice", "bob"],
                move |[mut alice_central, mut bob_central]| {
                    Box::pin(async move {
                        let id = conversation_id();
                        alice_central
                            .new_conversation(id.clone(), case.credential_type, case.cfg.clone())
                            .await
                            .unwrap();
                        alice_central
                            .invite(&id, &mut bob_central, case.custom_cfg())
                            .await
                            .unwrap();

                        let MlsCommitBundle { commit, .. } = bob_central
                            .remove_members_from_conversation(&id, &[alice_central.read_client_id()])
                            .await
                            .unwrap();
                        let MlsConversationDecryptMessage { is_active, .. } = alice_central
                            .decrypt_message(&id, commit.to_bytes().unwrap())
                            .await
                            .unwrap();
                        assert!(!is_active)
                    })
                },
            )
            .await
        }
    }

    pub mod commit {
        use super::*;

        #[apply(all_cred_cipher)]
        #[wasm_bindgen_test]
        pub async fn decrypting_a_commit_should_succeed(case: TestCase) {
            run_test_with_client_ids(
                case.clone(),
                ["alice", "bob"],
                move |[mut alice_central, mut bob_central]| {
                    Box::pin(async move {
                        let id = conversation_id();
                        alice_central
                            .new_conversation(id.clone(), case.credential_type, case.cfg.clone())
                            .await
                            .unwrap();
                        alice_central
                            .invite(&id, &mut bob_central, case.custom_cfg())
                            .await
                            .unwrap();

                        let epoch_before = alice_central.conversation_epoch(&id).await.unwrap();

                        let MlsCommitBundle { commit, .. } = alice_central.update_keying_material(&id).await.unwrap();
                        alice_central.commit_accepted(&id).await.unwrap();

                        let decrypted = bob_central
                            .decrypt_message(&id, commit.to_bytes().unwrap())
                            .await
                            .unwrap();
                        let epoch_after = bob_central.conversation_epoch(&id).await.unwrap();
                        assert_eq!(epoch_after, epoch_before + 1);
                        assert!(decrypted.has_epoch_changed);
                        assert!(decrypted.delay.is_none());
                        assert!(decrypted.app_msg.is_none());

                        alice_central.verify_sender_identity(&case, &decrypted);
                    })
                },
            )
            .await
        }

        #[apply(all_cred_cipher)]
        #[wasm_bindgen_test]
        pub async fn decrypting_a_commit_should_clear_pending_commit(case: TestCase) {
            run_test_with_client_ids(
                case.clone(),
                ["alice", "bob", "charlie", "debbie"],
                move |[mut alice_central, mut bob_central, charlie_central, debbie_central]| {
                    Box::pin(async move {
                        let id = conversation_id();
                        alice_central
                            .new_conversation(id.clone(), case.credential_type, case.cfg.clone())
                            .await
                            .unwrap();
                        alice_central
                            .invite(&id, &mut bob_central, case.custom_cfg())
                            .await
                            .unwrap();

                        // Alice creates a commit which will be superseded by Bob's one
                        let charlie = charlie_central.rand_member().await;
                        let debbie = debbie_central.rand_member().await;
                        alice_central
                            .add_members_to_conversation(&id, &mut [charlie.clone()])
                            .await
                            .unwrap();
                        assert!(alice_central.pending_commit(&id).await.is_some());

                        let add_debbie_commit = bob_central
                            .add_members_to_conversation(&id, &mut [debbie.clone()])
                            .await
                            .unwrap()
                            .commit;
                        let decrypted = alice_central
                            .decrypt_message(&id, add_debbie_commit.to_bytes().unwrap())
                            .await
                            .unwrap();
                        // Now Debbie should be in members and not Charlie
                        assert!(alice_central
                            .get_conversation_unchecked(&id)
                            .await
                            .members()
                            .get(&debbie.id)
                            .is_some());
                        assert!(alice_central
                            .get_conversation_unchecked(&id)
                            .await
                            .members()
                            .get(&charlie.id)
                            .is_none());
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
                move |[mut alice_central, mut bob_central, mut charlie_central]| {
                    Box::pin(async move {
                        let id = conversation_id();
                        alice_central
                            .new_conversation(id.clone(), case.credential_type, case.cfg.clone())
                            .await
                            .unwrap();
                        alice_central
                            .invite(&id, &mut bob_central, case.custom_cfg())
                            .await
                            .unwrap();

                        // Alice will create a commit to add Charlie
                        // Bob will create a commit which will be accepted first by DS so Alice will decrypt it
                        // Then Alice will renew the proposal in her pending commit
                        let charlie = charlie_central.rand_member().await;

                        let bob_commit = bob_central.update_keying_material(&id).await.unwrap().commit;
                        bob_central.commit_accepted(&id).await.unwrap();
                        // let commit_epoch = bob_commit.epoch();

                        // Alice propose to add Charlie
                        alice_central
                            .add_members_to_conversation(&id, &mut [charlie.clone()])
                            .await
                            .unwrap();
                        assert!(alice_central.pending_commit(&id).await.is_some());

                        // But first she receives Bob commit
                        let MlsConversationDecryptMessage { proposals, delay, .. } = alice_central
                            .decrypt_message(&id, bob_commit.to_bytes().unwrap())
                            .await
                            .unwrap();
                        // So Charlie has not been added to the group
                        assert!(alice_central
                            .get_conversation_unchecked(&id)
                            .await
                            .members()
                            .get(&charlie.id)
                            .is_none());
                        // Make sure we are suggesting a commit delay
                        assert!(delay.is_some());

                        // But its proposal to add Charlie has been renewed and is also in store
                        assert!(!proposals.is_empty());
                        assert_eq!(alice_central.pending_proposals(&id).await.len(), 1);
                        assert!(alice_central.pending_commit(&id).await.is_none());
                        // assert_eq!(
                        //     commit_epoch.as_u64() + 1,
                        //     proposals.first().unwrap().proposal.epoch().as_u64()
                        // );

                        // Let's commit this proposal to see if it works
                        for p in proposals {
                            // But first, proposals have to be fan out to Bob
                            bob_central
                                .decrypt_message(&id, p.proposal.to_bytes().unwrap())
                                .await
                                .unwrap();
                        }

                        let MlsCommitBundle { commit, welcome, .. } =
                            alice_central.commit_pending_proposals(&id).await.unwrap().unwrap();
                        alice_central.commit_accepted(&id).await.unwrap();
                        // Charlie is now in the group
                        assert!(alice_central
                            .get_conversation_unchecked(&id)
                            .await
                            .members()
                            .get(&charlie.id)
                            .is_some());

                        let decrypted = bob_central
                            .decrypt_message(&id, commit.to_bytes().unwrap())
                            .await
                            .unwrap();
                        // Bob also has Charlie in the group
                        assert!(bob_central
                            .get_conversation_unchecked(&id)
                            .await
                            .members()
                            .get(&charlie.id)
                            .is_some());
                        assert!(decrypted.has_epoch_changed);

                        // Charlie can join with the Welcome from renewed Add proposal
                        let id = charlie_central
                            .process_welcome_message(welcome.unwrap().into(), case.custom_cfg())
                            .await
                            .unwrap();
                        assert!(charlie_central.try_talk_to(&id, &mut alice_central).await.is_ok());
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
                move |[mut alice_central, mut bob_central, charlie_central]| {
                    Box::pin(async move {
                        let id = conversation_id();
                        alice_central
                            .new_conversation(id.clone(), case.credential_type, case.cfg.clone())
                            .await
                            .unwrap();
                        alice_central
                            .invite(&id, &mut bob_central, case.custom_cfg())
                            .await
                            .unwrap();

                        // Bob will create a proposal to add Charlie
                        // Alice will decrypt this proposal
                        // Then Bob will create a commit to update
                        // Alice will decrypt the commit but musn't renew the proposal to add Charlie
                        let charlie_kp = charlie_central.get_one_key_package(&case).await;

                        let add_charlie_proposal = bob_central
                            .new_proposal(&id, MlsProposal::Add(charlie_kp))
                            .await
                            .unwrap();
                        alice_central
                            .decrypt_message(&id, add_charlie_proposal.proposal.to_bytes().unwrap())
                            .await
                            .unwrap();

                        let MlsCommitBundle { commit, .. } = bob_central.update_keying_material(&id).await.unwrap();
                        let MlsConversationDecryptMessage {
                            proposals,
                            delay,
                            has_epoch_changed,
                            ..
                        } = alice_central
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
                            .new_conversation(id.clone(), case.credential_type, case.cfg.clone())
                            .await
                            .unwrap();
                        alice_central
                            .invite(&id, &mut bob_central, case.custom_cfg())
                            .await
                            .unwrap();

                        // Alice will create a proposal to add Charlie
                        // Bob will create a commit which Alice will decrypt
                        // Then Alice will renew her proposal
                        let bob_commit = bob_central.update_keying_material(&id).await.unwrap().commit;
                        bob_central.commit_accepted(&id).await.unwrap();
                        let commit_epoch = bob_commit.epoch().unwrap();

                        // Alice propose to add Charlie
                        let charlie_kp = charlie_central.get_one_key_package(&case).await;
                        alice_central
                            .new_proposal(&id, MlsProposal::Add(charlie_kp))
                            .await
                            .unwrap();
                        assert_eq!(alice_central.pending_proposals(&id).await.len(), 1);

                        // But first she receives Bob commit
                        let MlsConversationDecryptMessage { proposals, delay, .. } = alice_central
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
                            .decrypt_message(&id, renewed_proposal.proposal.to_bytes().unwrap())
                            .await
                            .unwrap();
                        assert_eq!(bob_central.pending_proposals(&id).await.len(), 1);
                        let MlsCommitBundle { commit, .. } =
                            bob_central.commit_pending_proposals(&id).await.unwrap().unwrap();
                        let decrypted = alice_central
                            .decrypt_message(&id, commit.to_bytes().unwrap())
                            .await
                            .unwrap();
                        // Charlie is now in the group
                        assert!(alice_central
                            .get_conversation_unchecked(&id)
                            .await
                            .members()
                            .get::<MemberId>(&charlie_central.read_client_id().into())
                            .is_some());

                        // Bob also has Charlie in the group
                        bob_central.commit_accepted(&id).await.unwrap();
                        assert!(bob_central
                            .get_conversation_unchecked(&id)
                            .await
                            .members()
                            .get::<MemberId>(&charlie_central.read_client_id().into())
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
                move |[mut alice_central, mut bob_central, charlie_central]| {
                    Box::pin(async move {
                        let id = conversation_id();
                        alice_central
                            .new_conversation(id.clone(), case.credential_type, case.cfg.clone())
                            .await
                            .unwrap();
                        alice_central
                            .invite(&id, &mut bob_central, case.custom_cfg())
                            .await
                            .unwrap();

                        // DS will create an external proposal to add Charlie
                        // But meanwhile Bob, before receiving the external proposal,
                        // will create a commit and send it to Alice.
                        // Alice will not renew the external proposal
                        let ext_proposal = charlie_central
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
                            .decrypt_message(&id, ext_proposal.to_bytes().unwrap())
                            .await
                            .unwrap();
                        assert_eq!(alice_central.pending_proposals(&id).await.len(), 1);

                        let MlsCommitBundle { commit, .. } = bob_central.update_keying_material(&id).await.unwrap();
                        let alice_renewed_proposals = alice_central
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
        pub async fn should_not_return_sender_client_id(case: TestCase) {
            run_test_with_client_ids(
                case.clone(),
                ["alice", "bob"],
                move |[mut alice_central, mut bob_central]| {
                    Box::pin(async move {
                        let id = conversation_id();
                        alice_central
                            .new_conversation(id.clone(), case.credential_type, case.cfg.clone())
                            .await
                            .unwrap();
                        alice_central
                            .invite(&id, &mut bob_central, case.custom_cfg())
                            .await
                            .unwrap();

                        let commit = alice_central.update_keying_material(&id).await.unwrap().commit;

                        let sender_client_id = bob_central
                            .decrypt_message(&id, commit.to_bytes().unwrap())
                            .await
                            .unwrap()
                            .sender_client_id;
                        assert!(sender_client_id.is_none());
                    })
                },
            )
            .await
        }
    }

    pub mod external_proposal {
        use super::*;

        #[apply(all_cred_cipher)]
        #[wasm_bindgen_test]
        pub async fn can_decrypt_external_proposal(case: TestCase) {
            run_test_with_client_ids(
                case.clone(),
                ["alice", "bob", "alice2"],
                move |[mut alice_central, mut bob_central, alice2_central]| {
                    Box::pin(async move {
                        let id = conversation_id();
                        alice_central
                            .new_conversation(id.clone(), case.credential_type, case.cfg.clone())
                            .await
                            .unwrap();
                        alice_central
                            .invite(&id, &mut bob_central, case.custom_cfg())
                            .await
                            .unwrap();

                        let epoch = alice_central.get_conversation_unchecked(&id).await.group.epoch();
                        let ext_proposal = alice2_central
                            .new_external_add_proposal(id.clone(), epoch, case.ciphersuite(), case.credential_type)
                            .await
                            .unwrap();

                        let decrypted = alice_central
                            .decrypt_message(&id, &ext_proposal.to_bytes().unwrap())
                            .await
                            .unwrap();
                        assert!(decrypted.app_msg.is_none());
                        assert!(decrypted.delay.is_some());

                        let decrypted = bob_central
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

        #[apply(all_cred_cipher)]
        #[wasm_bindgen_test]
        pub async fn cannot_decrypt_proposal_no_callback(case: TestCase) {
            run_test_with_client_ids(
                case.clone(),
                ["alice", "bob", "alice2"],
                move |[mut alice_central, mut bob_central, alice2_central]| {
                    Box::pin(async move {
                        let id = conversation_id();

                        alice_central
                            .new_conversation(id.clone(), case.credential_type, case.cfg.clone())
                            .await
                            .unwrap();
                        alice_central
                            .invite(&id, &mut bob_central, case.custom_cfg())
                            .await
                            .unwrap();

                        let epoch = alice_central.get_conversation_unchecked(&id).await.group.epoch();
                        let message = alice2_central
                            .new_external_add_proposal(id.clone(), epoch, case.ciphersuite(), case.credential_type)
                            .await
                            .unwrap();

                        alice_central.callbacks = None;
                        let error = alice_central
                            .decrypt_message(&id, &message.to_bytes().unwrap())
                            .await
                            .unwrap_err();

                        assert!(matches!(error, CryptoError::CallbacksNotSet));

                        bob_central.callbacks = None;
                        let error = bob_central
                            .decrypt_message(&id, &message.to_bytes().unwrap())
                            .await
                            .unwrap_err();

                        assert!(matches!(error, CryptoError::CallbacksNotSet));
                    })
                },
            )
            .await
        }

        #[apply(all_cred_cipher)]
        #[wasm_bindgen_test]
        pub async fn cannot_decrypt_proposal_validation(case: TestCase) {
            run_test_with_client_ids(
                case.clone(),
                ["alice", "bob", "alice2"],
                move |[mut alice_central, mut bob_central, alice2_central]| {
                    Box::pin(async move {
                        let id = conversation_id();
                        alice_central.callbacks(Box::new(ValidationCallbacks {
                            client_is_existing_group_user: false,
                            ..Default::default()
                        }));

                        alice_central
                            .new_conversation(id.clone(), case.credential_type, case.cfg.clone())
                            .await
                            .unwrap();
                        alice_central
                            .invite(&id, &mut bob_central, case.custom_cfg())
                            .await
                            .unwrap();

                        let epoch = alice_central.get_conversation_unchecked(&id).await.group.epoch();
                        let external_proposal = alice2_central
                            .new_external_add_proposal(id.clone(), epoch, case.ciphersuite(), case.credential_type)
                            .await
                            .unwrap();

                        let error = alice_central
                            .decrypt_message(&id, &external_proposal.to_bytes().unwrap())
                            .await
                            .unwrap_err();

                        assert!(matches!(error, CryptoError::UnauthorizedExternalAddProposal));

                        bob_central.callbacks = None;
                        let error = bob_central
                            .decrypt_message(&id, &external_proposal.to_bytes().unwrap())
                            .await
                            .unwrap_err();

                        assert!(matches!(error, CryptoError::CallbacksNotSet));
                    })
                },
            )
            .await
        }
    }

    pub mod proposal {
        use super::*;

        // Ensures decrypting an proposal is durable
        #[apply(all_cred_cipher)]
        #[wasm_bindgen_test]
        pub async fn can_decrypt_proposal(case: TestCase) {
            run_test_with_client_ids(
                case.clone(),
                ["alice", "bob", "charlie"],
                move |[mut alice_central, mut bob_central, charlie_central]| {
                    Box::pin(async move {
                        let id = conversation_id();
                        alice_central
                            .new_conversation(id.clone(), case.credential_type, case.cfg.clone())
                            .await
                            .unwrap();
                        alice_central
                            .invite(&id, &mut bob_central, case.custom_cfg())
                            .await
                            .unwrap();

                        let charlie_kp = charlie_central.get_one_key_package(&case).await;
                        let proposal = alice_central
                            .new_proposal(&id, MlsProposal::Add(charlie_kp))
                            .await
                            .unwrap()
                            .proposal;

                        let decrypted = bob_central
                            .decrypt_message(&id, proposal.to_bytes().unwrap())
                            .await
                            .unwrap();

                        assert_eq!(bob_central.get_conversation_unchecked(&id).await.members().len(), 2);
                        // if 'decrypt_message' is not durable the commit won't contain the add proposal
                        bob_central.commit_pending_proposals(&id).await.unwrap().unwrap();
                        bob_central.commit_accepted(&id).await.unwrap();
                        assert_eq!(bob_central.get_conversation_unchecked(&id).await.members().len(), 3);
                        assert!(!decrypted.has_epoch_changed);

                        alice_central.verify_sender_identity(&case, &decrypted);
                    })
                },
            )
            .await
        }

        #[apply(all_cred_cipher)]
        #[wasm_bindgen_test]
        pub async fn should_not_return_sender_client_id(case: TestCase) {
            run_test_with_client_ids(
                case.clone(),
                ["alice", "bob"],
                move |[mut alice_central, mut bob_central]| {
                    Box::pin(async move {
                        let id = conversation_id();
                        alice_central
                            .new_conversation(id.clone(), case.credential_type, case.cfg.clone())
                            .await
                            .unwrap();
                        alice_central
                            .invite(&id, &mut bob_central, case.custom_cfg())
                            .await
                            .unwrap();

                        let proposal = alice_central
                            .new_proposal(&id, MlsProposal::Update)
                            .await
                            .unwrap()
                            .proposal;

                        let sender_client_id = bob_central
                            .decrypt_message(&id, proposal.to_bytes().unwrap())
                            .await
                            .unwrap()
                            .sender_client_id;
                        assert!(sender_client_id.is_none());
                    })
                },
            )
            .await
        }
    }

    pub mod app_message {
        use super::*;

        #[apply(all_cred_cipher)]
        #[wasm_bindgen_test]
        pub async fn can_decrypt_app_message(case: TestCase) {
            run_test_with_client_ids(
                case.clone(),
                ["alice", "bob"],
                move |[mut alice_central, mut bob_central]| {
                    Box::pin(async move {
                        let id = conversation_id();
                        alice_central
                            .new_conversation(id.clone(), case.credential_type, case.cfg.clone())
                            .await
                            .unwrap();
                        alice_central
                            .invite(&id, &mut bob_central, case.custom_cfg())
                            .await
                            .unwrap();

                        let msg = b"Hello bob";
                        let encrypted = alice_central.encrypt_message(&id, msg).await.unwrap();
                        assert_ne!(&msg[..], &encrypted[..]);
                        let decrypted = bob_central.decrypt_message(&id, encrypted).await.unwrap();
                        let dec_msg = decrypted.app_msg.as_ref().unwrap().as_slice();
                        assert_eq!(dec_msg, &msg[..]);
                        assert!(!decrypted.has_epoch_changed);
                        alice_central.verify_sender_identity(&case, &decrypted);

                        let msg = b"Hello alice";
                        let encrypted = bob_central.encrypt_message(&id, msg).await.unwrap();
                        assert_ne!(&msg[..], &encrypted[..]);
                        let decrypted = alice_central.decrypt_message(&id, encrypted).await.unwrap();
                        let dec_msg = decrypted.app_msg.as_ref().unwrap().as_slice();
                        assert_eq!(dec_msg, &msg[..]);
                        assert!(!decrypted.has_epoch_changed);
                        bob_central.verify_sender_identity(&case, &decrypted);
                    })
                },
            )
            .await
        }

        // Ensures decrypting an application message is durable
        #[apply(all_cred_cipher)]
        #[wasm_bindgen_test]
        pub async fn cannot_decrypt_app_message_twice(case: TestCase) {
            run_test_with_client_ids(
                case.clone(),
                ["alice", "bob"],
                move |[mut alice_central, mut bob_central]| {
                    Box::pin(async move {
                        let id = conversation_id();
                        alice_central
                            .new_conversation(id.clone(), case.credential_type, case.cfg.clone())
                            .await
                            .unwrap();
                        alice_central
                            .invite(&id, &mut bob_central, case.custom_cfg())
                            .await
                            .unwrap();

                        let msg = b"Hello bob";
                        let encrypted = alice_central.encrypt_message(&id, msg).await.unwrap();
                        assert_ne!(&msg[..], &encrypted[..]);
                        let decrypt_once = bob_central.decrypt_message(&id, encrypted.clone()).await;
                        assert!(decrypt_once.is_ok());
                        let decrypt_twice = bob_central.decrypt_message(&id, encrypted).await;
                        assert!(matches!(decrypt_twice.unwrap_err(), CryptoError::GenerationOutOfBound))
                    })
                },
            )
            .await
        }

        #[apply(all_cred_cipher)]
        #[wasm_bindgen_test]
        pub async fn cannot_decrypt_app_message_after_rejoining(case: TestCase) {
            run_test_with_client_ids(
                case.clone(),
                ["alice", "bob"],
                move |[mut alice_central, mut bob_central]| {
                    Box::pin(async move {
                        let id = conversation_id();
                        alice_central
                            .new_conversation(id.clone(), case.credential_type, case.cfg.clone())
                            .await
                            .unwrap();
                        alice_central
                            .invite(&id, &mut bob_central, case.custom_cfg())
                            .await
                            .unwrap();

                        // encrypt a message in epoch 1
                        let msg = b"Hello bob";
                        let encrypted = alice_central.encrypt_message(&id, msg).await.unwrap();

                        // Now Bob will rejoin the group and try to decrypt Alice's message
                        // in epoch 2 which should fail
                        let gi = alice_central.get_group_info(&id).await;
                        bob_central
                            .join_by_external_commit(gi.into(), case.custom_cfg(), case.credential_type)
                            .await
                            .unwrap();
                        bob_central.merge_pending_group_from_external_commit(&id).await.unwrap();

                        // fails because of Forward Secrecy
                        let decrypt = bob_central.decrypt_message(&id, &encrypted).await;
                        assert!(matches!(decrypt.unwrap_err(), CryptoError::DecryptionError));
                    })
                },
            )
            .await
        }

        #[apply(all_cred_cipher)]
        #[wasm_bindgen_test]
        pub async fn cannot_decrypt_app_message_from_future_epoch(case: TestCase) {
            run_test_with_client_ids(
                case.clone(),
                ["alice", "bob"],
                move |[mut alice_central, mut bob_central]| {
                    Box::pin(async move {
                        let id = conversation_id();
                        alice_central
                            .new_conversation(id.clone(), case.credential_type, case.cfg.clone())
                            .await
                            .unwrap();
                        alice_central
                            .invite(&id, &mut bob_central, case.custom_cfg())
                            .await
                            .unwrap();

                        // only Alice which change epoch without notifying Bob
                        let commit = alice_central.update_keying_material(&id).await.unwrap().commit;
                        alice_central.commit_accepted(&id).await.unwrap();

                        // Now in epoch 2 Alice will encrypt a message
                        let msg = b"Hello bob";
                        let encrypted = alice_central.encrypt_message(&id, msg).await.unwrap();

                        // which Bob cannot decrypt because of Post CompromiseSecurity
                        let decrypt = bob_central.decrypt_message(&id, &encrypted).await;
                        assert!(matches!(decrypt.unwrap_err(), CryptoError::WrongEpoch));

                        bob_central
                            .decrypt_message(&id, commit.to_bytes().unwrap())
                            .await
                            .unwrap();
                        let decrypted = bob_central.decrypt_message(&id, encrypted).await.unwrap();

                        assert_eq!(&decrypted.app_msg.unwrap(), msg);
                    })
                },
            )
            .await
        }

        #[apply(all_cred_cipher)]
        #[wasm_bindgen_test]
        pub async fn can_decrypt_app_message_in_any_order(mut case: TestCase) {
            // otherwise the test would fail because we decrypt messages in reverse order which is
            // kinda dropping them
            case.cfg.custom.maximum_forward_distance = 0;
            run_test_with_client_ids(
                case.clone(),
                ["alice", "bob"],
                move |[mut alice_central, mut bob_central]| {
                    Box::pin(async move {
                        let id = conversation_id();
                        alice_central
                            .new_conversation(id.clone(), case.credential_type, case.cfg.clone())
                            .await
                            .unwrap();
                        alice_central
                            .invite(&id, &mut bob_central, case.custom_cfg())
                            .await
                            .unwrap();

                        let out_of_order_tolerance = case.custom_cfg().out_of_order_tolerance;
                        let nb_messages = out_of_order_tolerance * 2;
                        let mut messages = vec![];

                        // stack up encrypted messages..
                        for i in 0..nb_messages {
                            let msg = format!("Hello {i}");
                            let encrypted = alice_central.encrypt_message(&id, &msg).await.unwrap();
                            messages.push((msg, encrypted));
                        }

                        // ..then unstack them to see out_of_order_tolerance come into play
                        messages.reverse();
                        for (i, (original, encrypted)) in messages.iter().enumerate() {
                            let decrypt = bob_central.decrypt_message(&id, encrypted).await;
                            if i > out_of_order_tolerance as usize {
                                let decrypted = decrypt.unwrap().app_msg.unwrap();
                                assert_eq!(decrypted, original.as_bytes());
                            } else {
                                assert!(matches!(decrypt.unwrap_err(), CryptoError::GenerationOutOfBound))
                            }
                        }
                    })
                },
            )
            .await
        }

        #[apply(all_cred_cipher)]
        #[wasm_bindgen_test]
        pub async fn returns_sender_client_id(case: TestCase) {
            run_test_with_client_ids(
                case.clone(),
                ["alice", "bob"],
                move |[mut alice_central, mut bob_central]| {
                    Box::pin(async move {
                        let id = conversation_id();
                        alice_central
                            .new_conversation(id.clone(), case.credential_type, case.cfg.clone())
                            .await
                            .unwrap();
                        alice_central
                            .invite(&id, &mut bob_central, case.custom_cfg())
                            .await
                            .unwrap();

                        let msg = b"Hello bob";
                        let encrypted = alice_central.encrypt_message(&id, msg).await.unwrap();
                        assert_ne!(&msg[..], &encrypted[..]);

                        let sender_client_id = bob_central
                            .decrypt_message(&id, encrypted)
                            .await
                            .unwrap()
                            .sender_client_id
                            .unwrap();
                        assert_eq!(sender_client_id, alice_central.read_client_id());
                    })
                },
            )
            .await
        }
    }

    pub mod epoch_sync {
        use crate::mls::conversation::config::MAX_PAST_EPOCHS;

        use super::*;

        #[apply(all_cred_cipher)]
        #[wasm_bindgen_test]
        pub async fn should_throw_specialized_error_when_epoch_too_old(mut case: TestCase) {
            case.cfg.custom.out_of_order_tolerance = 0;
            run_test_with_client_ids(
                case.clone(),
                ["alice", "bob"],
                move |[mut alice_central, mut bob_central]| {
                    Box::pin(async move {
                        let id = conversation_id();
                        alice_central
                            .new_conversation(id.clone(), case.credential_type, case.cfg.clone())
                            .await
                            .unwrap();
                        alice_central
                            .invite(&id, &mut bob_central, case.custom_cfg())
                            .await
                            .unwrap();

                        // Alice encrypts a message to Bob
                        let bob_message1 = alice_central.encrypt_message(&id, b"Hello Bob").await.unwrap();
                        let bob_message2 = alice_central.encrypt_message(&id, b"Hello again Bob").await.unwrap();

                        // Move group's epoch forward by self updating
                        for _ in 0..MAX_PAST_EPOCHS {
                            let commit = alice_central.update_keying_material(&id).await.unwrap().commit;
                            alice_central.commit_accepted(&id).await.unwrap();
                            bob_central
                                .decrypt_message(&id, commit.to_bytes().unwrap())
                                .await
                                .unwrap();
                        }
                        // Decrypt should work
                        let decrypt = bob_central.decrypt_message(&id, &bob_message1).await.unwrap();
                        assert_eq!(decrypt.app_msg.unwrap(), b"Hello Bob");

                        // Moving the epochs once more should cause an error
                        let commit = alice_central.update_keying_material(&id).await.unwrap().commit;
                        alice_central.commit_accepted(&id).await.unwrap();
                        bob_central
                            .decrypt_message(&id, commit.to_bytes().unwrap())
                            .await
                            .unwrap();

                        let decrypt = bob_central.decrypt_message(&id, &bob_message2).await;
                        assert!(matches!(decrypt.unwrap_err(), CryptoError::MessageEpochTooOld));
                    })
                },
            )
            .await
        }

        #[apply(all_cred_cipher)]
        #[wasm_bindgen_test]
        pub async fn should_throw_specialized_error_when_epoch_desynchronized(mut case: TestCase) {
            case.cfg.custom.out_of_order_tolerance = 0;
            run_test_with_client_ids(
                case.clone(),
                ["alice", "bob"],
                move |[mut alice_central, mut bob_central]| {
                    Box::pin(async move {
                        let id = conversation_id();
                        alice_central
                            .new_conversation(id.clone(), case.credential_type, case.cfg.clone())
                            .await
                            .unwrap();
                        alice_central
                            .invite(&id, &mut bob_central, case.custom_cfg())
                            .await
                            .unwrap();

                        // Alice generates a bunch of soon to be outdated messages
                        let old_proposal = alice_central
                            .new_proposal(&id, MlsProposal::Update)
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
                            .update_keying_material(&id)
                            .await
                            .unwrap()
                            .commit
                            .to_bytes()
                            .unwrap();
                        alice_central.clear_pending_commit(&id).await.unwrap();
                        let outdated_messages = vec![old_proposal, old_commit];

                        // Now let's jump to next epoch
                        let commit = alice_central.update_keying_material(&id).await.unwrap().commit;
                        alice_central.commit_accepted(&id).await.unwrap();
                        bob_central
                            .decrypt_message(&id, commit.to_bytes().unwrap())
                            .await
                            .unwrap();

                        // trying to consume outdated messages should fail with a dedicated error
                        for outdated in outdated_messages {
                            let decrypt = bob_central.decrypt_message(&id, &outdated).await;
                            assert!(matches!(decrypt.unwrap_err(), CryptoError::WrongEpoch));
                        }
                    })
                },
            )
            .await
        }
    }

    pub mod expired {
        use crate::prelude::MlsCredentialType;
        use openmls::prelude::ProcessMessageError;
        use openmls_traits::OpenMlsCryptoProvider;

        use super::*;

        #[apply(all_cred_cipher)]
        #[wasm_bindgen_test]
        #[ignore]
        pub async fn should_fail_when_message_signed_by_expired_key_package(case: TestCase) {
            if matches!(case.credential_type, MlsCredentialType::X509) {
                run_test_with_client_ids(
                    case.clone(),
                    ["alice", "bob"],
                    move |[mut alice_central, mut bob_central]| {
                        Box::pin(async move {
                            let id = conversation_id();
                            alice_central
                                .new_conversation(id.clone(), case.credential_type, case.cfg.clone())
                                .await
                                .unwrap();

                            // Bob will have generated a bunch of long to expire KeyPackage, no suitable for a test.
                            // So we will prune all his KeyPackages and replace them by shorter ones
                            let bob_client = bob_central.mls_client.as_mut().unwrap();
                            let bob_kps = bob_client.find_keypackages(&bob_central.mls_backend).await.unwrap();
                            let bob_kp_refs = bob_kps
                                .iter()
                                .map(|k| k.hash_ref(bob_central.mls_backend.crypto()).unwrap())
                                .collect::<Vec<KeyPackageRef>>();
                            bob_client
                                .prune_keypackages(&bob_kp_refs, &bob_central.mls_backend)
                                .await
                                .unwrap();
                            let bob_nb_kps = bob_client
                                .valid_keypackages_count(&bob_central.mls_backend, case.ciphersuite())
                                .await
                                .unwrap();
                            // Alright Bob does not have any KeyPackage
                            assert_eq!(bob_nb_kps, 0);

                            bob_client.set_keypackage_lifetime(Duration::from_secs(2));

                            // Now Bob will have shorter KeyPackages. Let's add Bob to the group before those expire
                            alice_central
                                .invite(&id, &mut bob_central, case.custom_cfg())
                                .await
                                .unwrap();

                            // Now Bob will generate AND SIGN some messages with a signature key
                            // in his soon to expire KeyPackage
                            let msg = b"Hello alice";
                            let expired_app_msg = bob_central.encrypt_message(&id, msg).await.unwrap();
                            let expired_proposal = bob_central
                                .new_proposal(&id, MlsProposal::Update)
                                .await
                                .unwrap()
                                .proposal
                                .to_bytes()
                                .unwrap();
                            bob_central
                                .get_conversation_unchecked(&id)
                                .await
                                .group
                                .clear_pending_proposals();
                            let expired_commit = bob_central
                                .update_keying_material(&id)
                                .await
                                .unwrap()
                                .commit
                                .to_bytes()
                                .unwrap();
                            bob_central.clear_pending_commit(&id).await.unwrap();
                            let expired_handshakes = vec![expired_proposal, expired_commit];

                            // Sleep to trigger the expiration
                            async_std::task::sleep(Duration::from_secs(5)).await;

                            // Expired handshake messages should fail
                            for expired_handshake in expired_handshakes {
                                let decrypted = alice_central.decrypt_message(&id, expired_handshake).await;
                                if case.custom_cfg().wire_policy == MlsWirePolicy::Ciphertext {
                                    // Cannot return a precise error here this this could fail for so many reasons
                                    assert!(matches!(
                                        decrypted.unwrap_err(),
                                        CryptoError::MlsError(MlsError::MlsMessageError(
                                            ProcessMessageError::ValidationError(ValidationError::UnableToDecrypt(
                                                MessageDecryptionError::MalformedContent
                                            ))
                                        ))
                                    ));
                                } else {
                                    // Unfortunately this errors cannot be pattern matched because KeyPackage
                                    // expiry validation happens when TLS decoding
                                    assert!(matches!(
                                        decrypted.unwrap_err(),
                                        CryptoError::MlsError(MlsError::MlsMessageError(
                                            ProcessMessageError::ValidationError(ValidationError::UnableToDecrypt(_))
                                        ))
                                    ));
                                }
                            }

                            // So is expired application message
                            let decrypted = alice_central.decrypt_message(&id, expired_app_msg).await;
                            assert!(matches!(decrypted.unwrap_err(), CryptoError::InvalidKeyPackage));
                        })
                    },
                )
                .await
            }
        }
    }
}
