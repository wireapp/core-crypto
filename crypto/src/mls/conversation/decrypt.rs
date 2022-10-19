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
    framing::errors::MessageDecryptionError,
    prelude::{MlsMessageIn, ParseMessageError, ProcessedMessage, UnverifiedMessage, ValidationError},
};
use openmls_traits::OpenMlsCryptoProvider;

use mls_crypto_provider::MlsCryptoProvider;

use crate::{
    mls::{conversation::renew::Renew, ClientId, ConversationId, MlsCentral, MlsConversation},
    prelude::MlsProposalBundle,
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
    pub is_epoch_changed: bool,
}

/// Abstraction over a MLS group capable of decrypting a MLS message
impl MlsConversation {
    /// see [MlsCentral::decrypt_message]
    #[cfg_attr(test, crate::durable)]
    pub async fn decrypt_message(
        &mut self,
        message: impl AsRef<[u8]>,
        backend: &MlsCryptoProvider,
        callbacks: Option<&dyn CoreCryptoCallbacks>,
    ) -> CryptoResult<MlsConversationDecryptMessage> {
        let msg_in = openmls::framing::MlsMessageIn::try_from_bytes(message.as_ref()).map_err(MlsError::from)?;

        let parsed_message = self.parse_message(backend, msg_in)?;

        let sender_client_id = parsed_message.credential().map(|c| c.identity().into());

        let message = self
            .group
            .process_unverified_message(parsed_message, None, backend)
            .await
            .map_err(MlsError::from)?;

        let decrypted = match message {
            ProcessedMessage::ApplicationMessage(app_msg) => MlsConversationDecryptMessage {
                app_msg: Some(app_msg.into_bytes()),
                proposals: vec![],
                is_active: true,
                delay: None,
                sender_client_id,
                is_epoch_changed: false,
            },
            ProcessedMessage::ProposalMessage(proposal) => {
                self.validate_external_proposal(&proposal, callbacks, backend.crypto())?;
                self.group.store_pending_proposal(*proposal);

                MlsConversationDecryptMessage {
                    app_msg: None,
                    proposals: vec![],
                    is_active: true,
                    delay: self.compute_next_commit_delay(),
                    sender_client_id: None,
                    is_epoch_changed: false,
                }
            }
            ProcessedMessage::StagedCommitMessage(staged_commit) => {
                let valid_commit = staged_commit.clone();
                self.validate_external_commit(&valid_commit, sender_client_id, callbacks, backend.crypto())?;

                let pending_commit = self.group.pending_commit().cloned();
                #[allow(clippy::needless_collect)] // false positive
                let pending_proposals = self.self_pending_proposals().cloned().collect::<Vec<_>>();

                let self_kpr = self.group.key_package_ref().cloned();

                self.group.merge_staged_commit(*staged_commit).map_err(MlsError::from)?;

                let (proposals, update_self) = Renew::renew(
                    self_kpr,
                    pending_proposals.into_iter(),
                    pending_commit.as_ref(),
                    valid_commit.as_ref(),
                );
                let proposals = self
                    .renew_proposals_for_current_epoch(backend, proposals.into_iter(), update_self)
                    .await?;

                MlsConversationDecryptMessage {
                    app_msg: None,
                    proposals,
                    is_active: self.group.is_active(),
                    delay: self.compute_next_commit_delay(),
                    sender_client_id: None,
                    is_epoch_changed: true,
                }
            }
        };

        self.persist_group_when_changed(backend, false).await?;

        Ok(decrypted)
    }

    fn parse_message(&mut self, backend: &MlsCryptoProvider, msg_in: MlsMessageIn) -> CryptoResult<UnverifiedMessage> {
        self.group.parse_message(msg_in, backend).map_err(|e| match e {
            ParseMessageError::ValidationError(ValidationError::UnableToDecrypt(
                MessageDecryptionError::GenerationOutOfBound,
            )) => CryptoError::GenerationOutOfBound,
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
        let decrypt_message = Self::get_conversation_mut(&mut self.mls_groups, conversation_id)?
            .decrypt_message(
                message.as_ref(),
                &self.mls_backend,
                self.callbacks.as_ref().map(|boxed| boxed.as_ref()),
            )
            .await?;
        if !decrypt_message.is_active {
            self.mls_groups
                .remove(conversation_id)
                .ok_or(CryptoError::ImplementationError)?;
        }
        Ok(decrypt_message)
    }
}

#[cfg(test)]
pub mod tests {
    use wasm_bindgen_test::*;

    use crate::{mls::proposal::MlsProposal, prelude::handshake::MlsCommitBundle, test_utils::*};

    use super::*;

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
                            .new_conversation(id.clone(), case.cfg.clone())
                            .await
                            .unwrap();
                        alice_central
                            .invite(&id, case.cfg.clone(), &mut bob_central)
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
                            .new_conversation(id.clone(), case.cfg.clone())
                            .await
                            .unwrap();
                        alice_central
                            .invite(&id, case.cfg.clone(), &mut bob_central)
                            .await
                            .unwrap();

                        let MlsCommitBundle { commit, .. } = bob_central
                            .remove_members_from_conversation(&id, &["alice".into()])
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
        pub async fn decrypting_a_commit_should_clear_pending_commit(case: TestCase) {
            run_test_with_client_ids(
                case.clone(),
                ["alice", "bob", "charlie", "debbie"],
                move |[mut alice_central, mut bob_central, charlie_central, debbie_central]| {
                    Box::pin(async move {
                        let id = conversation_id();
                        alice_central
                            .new_conversation(id.clone(), case.cfg.clone())
                            .await
                            .unwrap();
                        alice_central
                            .invite(&id, case.cfg.clone(), &mut bob_central)
                            .await
                            .unwrap();

                        // Alice creates a commit which will be superseded by Bob's one
                        let charlie = charlie_central.rnd_member().await;
                        let debbie = debbie_central.rnd_member().await;
                        alice_central
                            .add_members_to_conversation(&id, &mut [charlie.clone()])
                            .await
                            .unwrap();
                        assert!(alice_central.pending_commit(&id).is_some());

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
                        assert!(alice_central[&id].members().get(&debbie.id).is_some());
                        assert!(alice_central[&id].members().get(&charlie.id).is_none());
                        // Previous commit to add Charlie has been discarded but its proposals will be renewed
                        assert!(alice_central.pending_commit(&id).is_none());
                        assert!(decrypted.is_epoch_changed)
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
                            .new_conversation(id.clone(), case.cfg.clone())
                            .await
                            .unwrap();
                        alice_central
                            .invite(&id, case.cfg.clone(), &mut bob_central)
                            .await
                            .unwrap();

                        // Alice will create a commit to add Charlie
                        // Bob will create a commit which will be accepted first by DS so Alice will decrypt it
                        // Then Alice will renew the proposal in her pending commit
                        let charlie = charlie_central.rnd_member().await;

                        let bob_commit = bob_central.update_keying_material(&id).await.unwrap().commit;
                        bob_central.commit_accepted(&id).await.unwrap();
                        let commit_epoch = bob_commit.epoch();

                        // Alice propose to add Charlie
                        alice_central
                            .add_members_to_conversation(&id, &mut [charlie.clone()])
                            .await
                            .unwrap();
                        assert!(alice_central.pending_commit(&id).is_some());

                        // But first she receives Bob commit
                        let MlsConversationDecryptMessage { proposals, delay, .. } = alice_central
                            .decrypt_message(&id, bob_commit.to_bytes().unwrap())
                            .await
                            .unwrap();
                        // So Charlie has not been added to the group
                        assert!(alice_central[&id].members().get(&charlie.id).is_none());
                        // Make sure we are suggesting a commit delay
                        assert!(delay.is_some());

                        // But its proposal to add Charlie has been renewed and is also in store
                        assert!(!proposals.is_empty());
                        assert_eq!(alice_central.pending_proposals(&id).len(), 1);
                        assert!(alice_central.pending_commit(&id).is_none());
                        assert_eq!(
                            commit_epoch.as_u64() + 1,
                            proposals.first().unwrap().proposal.epoch().as_u64()
                        );

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
                        assert!(alice_central[&id].members().get(&charlie.id).is_some());

                        let decrypted = bob_central
                            .decrypt_message(&id, commit.to_bytes().unwrap())
                            .await
                            .unwrap();
                        // Bob also has Charlie in the group
                        assert!(bob_central[&id].members().get(&charlie.id).is_some());
                        assert!(decrypted.is_epoch_changed);

                        // Charlie can join with the Welcome from renewed Add proposal
                        let id = charlie_central
                            .process_welcome_message(welcome.unwrap(), case.cfg.clone())
                            .await
                            .unwrap();
                        assert!(charlie_central.talk_to(&id, &mut alice_central).await.is_ok());
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
                            .new_conversation(id.clone(), case.cfg.clone())
                            .await
                            .unwrap();
                        alice_central
                            .invite(&id, case.cfg.clone(), &mut bob_central)
                            .await
                            .unwrap();

                        // Bob will create a proposal to add Charlie
                        // Alice will decrypt this proposal
                        // Then Bob will create a commit to update
                        // Alice will decrypt the commit but musn't renew the proposal to add Charlie
                        let charlie_kp = charlie_central.get_one_key_package().await;

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
                            is_epoch_changed,
                            ..
                        } = alice_central
                            .decrypt_message(&id, commit.to_bytes().unwrap())
                            .await
                            .unwrap();
                        assert!(proposals.is_empty());
                        assert!(delay.is_none());
                        assert!(alice_central.pending_proposals(&id).is_empty());
                        assert!(is_epoch_changed)
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
                            .new_conversation(id.clone(), case.cfg.clone())
                            .await
                            .unwrap();
                        alice_central
                            .invite(&id, case.cfg.clone(), &mut bob_central)
                            .await
                            .unwrap();

                        // Alice will create a proposal to add Charlie
                        // Bob will create a commit which Alice will decrypt
                        // Then Alice will renew her proposal
                        let bob_commit = bob_central.update_keying_material(&id).await.unwrap().commit;
                        bob_central.commit_accepted(&id).await.unwrap();
                        let commit_epoch = bob_commit.epoch();

                        // Alice propose to add Charlie
                        let charlie_kp = charlie_central.get_one_key_package().await;
                        alice_central
                            .new_proposal(&id, MlsProposal::Add(charlie_kp))
                            .await
                            .unwrap();
                        assert_eq!(alice_central.pending_proposals(&id).len(), 1);

                        // But first she receives Bob commit
                        let MlsConversationDecryptMessage { proposals, delay, .. } = alice_central
                            .decrypt_message(&id, bob_commit.to_bytes().unwrap())
                            .await
                            .unwrap();
                        // So Charlie has not been added to the group
                        assert!(alice_central[&id].members().get(&b"charlie".to_vec()).is_none());
                        // Make sure we are suggesting a commit delay
                        assert!(delay.is_some());

                        // But its proposal to add Charlie has been renewed and is also in store
                        assert!(!proposals.is_empty());
                        assert_eq!(alice_central.pending_proposals(&id).len(), 1);
                        let renewed_proposal = proposals.first().unwrap();
                        assert_eq!(commit_epoch.as_u64() + 1, renewed_proposal.proposal.epoch().as_u64());

                        // Let's use this proposal to see if it works
                        bob_central
                            .decrypt_message(&id, renewed_proposal.proposal.to_bytes().unwrap())
                            .await
                            .unwrap();
                        assert_eq!(bob_central.pending_proposals(&id).len(), 1);
                        let MlsCommitBundle { commit, .. } =
                            bob_central.commit_pending_proposals(&id).await.unwrap().unwrap();
                        let decrypted = alice_central
                            .decrypt_message(&id, commit.to_bytes().unwrap())
                            .await
                            .unwrap();
                        // Charlie is now in the group
                        assert!(alice_central[&id].members().get(&b"charlie".to_vec()).is_some());

                        // Bob also has Charlie in the group
                        bob_central.commit_accepted(&id).await.unwrap();
                        assert!(bob_central[&id].members().get(&b"charlie".to_vec()).is_some());
                        assert!(decrypted.is_epoch_changed);
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
                            .new_conversation(id.clone(), case.cfg.clone())
                            .await
                            .unwrap();
                        alice_central
                            .invite(&id, case.cfg.clone(), &mut bob_central)
                            .await
                            .unwrap();

                        // DS will create an external proposal to add Charlie
                        // But meanwhile Bob, before receiving the external proposal,
                        // will create a commit and send it to Alice.
                        // Alice will not renew the external proposal
                        let ext_proposal = charlie_central
                            .new_external_add_proposal(id.clone(), alice_central[&id].group.epoch())
                            .await
                            .unwrap();
                        assert!(alice_central.pending_proposals(&id).is_empty());
                        alice_central
                            .decrypt_message(&id, ext_proposal.to_bytes().unwrap())
                            .await
                            .unwrap();
                        assert_eq!(alice_central.pending_proposals(&id).len(), 1);

                        let MlsCommitBundle { commit, .. } = bob_central.update_keying_material(&id).await.unwrap();
                        let alice_renewed_proposals = alice_central
                            .decrypt_message(&id, commit.to_bytes().unwrap())
                            .await
                            .unwrap()
                            .proposals;
                        assert!(alice_renewed_proposals.is_empty());
                        assert!(alice_central.pending_proposals(&id).is_empty());
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
                            .new_conversation(id.clone(), case.cfg.clone())
                            .await
                            .unwrap();
                        alice_central
                            .invite(&id, case.cfg.clone(), &mut bob_central)
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

    pub mod decrypt_callback {
        use crate::{test_utils::ValidationCallbacks, CryptoError};

        use super::*;

        #[apply(all_cred_cipher)]
        #[wasm_bindgen_test]
        pub async fn can_decrypt_proposal(case: TestCase) {
            run_test_with_client_ids(
                case.clone(),
                ["alice", "bob", "alice2"],
                move |[mut alice_central, mut bob_central, alice2_central]| {
                    Box::pin(async move {
                        let id = conversation_id();
                        alice_central
                            .new_conversation(id.clone(), case.cfg.clone())
                            .await
                            .unwrap();
                        alice_central
                            .invite(&id, case.cfg.clone(), &mut bob_central)
                            .await
                            .unwrap();

                        let epoch = alice_central[&id].group.epoch();
                        let ext_proposal = alice2_central
                            .new_external_add_proposal(id.clone(), epoch)
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
                        assert!(!decrypted.is_epoch_changed)
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
                            .new_conversation(id.clone(), case.cfg.clone())
                            .await
                            .unwrap();
                        alice_central
                            .invite(&id, case.cfg.clone(), &mut bob_central)
                            .await
                            .unwrap();

                        let epoch = alice_central[&id].group.epoch();
                        let message = alice2_central
                            .new_external_add_proposal(id.clone(), epoch)
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
                            .new_conversation(id.clone(), case.cfg.clone())
                            .await
                            .unwrap();
                        alice_central
                            .invite(&id, case.cfg.clone(), &mut bob_central)
                            .await
                            .unwrap();

                        let epoch = alice_central[&id].group.epoch();
                        let external_proposal = alice2_central
                            .new_external_add_proposal(id.clone(), epoch)
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
                            .new_conversation(id.clone(), case.cfg.clone())
                            .await
                            .unwrap();
                        alice_central
                            .invite(&id, case.cfg.clone(), &mut bob_central)
                            .await
                            .unwrap();

                        let charlie_kp = charlie_central.get_one_key_package().await;
                        let proposal = alice_central
                            .new_proposal(&id, MlsProposal::Add(charlie_kp))
                            .await
                            .unwrap()
                            .proposal;

                        let decrypted = bob_central
                            .decrypt_message(&id, proposal.to_bytes().unwrap())
                            .await
                            .unwrap();

                        assert_eq!(bob_central[&id].members().len(), 2);
                        // if 'decrypt_message' is not durable the commit won't contain the add proposal
                        bob_central.commit_pending_proposals(&id).await.unwrap().unwrap();
                        bob_central.commit_accepted(&id).await.unwrap();
                        assert_eq!(bob_central[&id].members().len(), 3);
                        assert!(!decrypted.is_epoch_changed)
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
                            .new_conversation(id.clone(), case.cfg.clone())
                            .await
                            .unwrap();
                        alice_central
                            .invite(&id, case.cfg.clone(), &mut bob_central)
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
                            .new_conversation(id.clone(), case.cfg.clone())
                            .await
                            .unwrap();
                        alice_central
                            .invite(&id, case.cfg.clone(), &mut bob_central)
                            .await
                            .unwrap();

                        let msg = b"Hello bob";
                        let encrypted = alice_central.encrypt_message(&id, msg).await.unwrap();
                        assert_ne!(&msg[..], &encrypted[..]);
                        let decrypted = bob_central.decrypt_message(&id, encrypted).await.unwrap();
                        let dec_msg = decrypted.app_msg.unwrap();
                        assert_eq!(&dec_msg[..], &msg[..]);
                        assert!(!decrypted.is_epoch_changed);
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
                            .new_conversation(id.clone(), case.cfg.clone())
                            .await
                            .unwrap();
                        alice_central
                            .invite(&id, case.cfg.clone(), &mut bob_central)
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
        pub async fn can_decrypt_app_message_in_any_order(case: TestCase) {
            run_test_with_client_ids(
                case.clone(),
                ["alice", "bob"],
                move |[mut alice_central, mut bob_central]| {
                    Box::pin(async move {
                        let id = conversation_id();
                        alice_central
                            .new_conversation(id.clone(), case.cfg.clone())
                            .await
                            .unwrap();
                        alice_central
                            .invite(&id, case.cfg.clone(), &mut bob_central)
                            .await
                            .unwrap();

                        let msg1 = b"Hello bob once";
                        let encrypted1 = alice_central.encrypt_message(&id, msg1).await.unwrap();
                        let msg2 = b"Hello bob twice";
                        let encrypted2 = alice_central.encrypt_message(&id, msg2).await.unwrap();

                        let decrypted2 = bob_central
                            .decrypt_message(&id, encrypted2)
                            .await
                            .unwrap()
                            .app_msg
                            .unwrap();
                        assert_eq!(&decrypted2[..], &msg2[..]);
                        let decrypted1 = bob_central
                            .decrypt_message(&id, encrypted1)
                            .await
                            .unwrap()
                            .app_msg
                            .unwrap();
                        assert_eq!(&decrypted1[..], &msg1[..]);
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
                            .new_conversation(id.clone(), case.cfg.clone())
                            .await
                            .unwrap();
                        alice_central
                            .invite(&id, case.cfg.clone(), &mut bob_central)
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
                        assert_eq!(sender_client_id, b"alice"[..].into());
                    })
                },
            )
            .await
        }
    }
}
