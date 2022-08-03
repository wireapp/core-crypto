//! MLS defines 3 kind of messages: Proposal, Commits and Application messages. Since they can (should)
//! be all encrypted we need to first decrypt them before deciding what to do with them.
//!
//! This table summarizes when a MLS group can decrypt any message:
//!
//! | can decrypt ?     | 0 pend. Commit | 1 pend. Commit |
//! |-------------------|----------------|----------------|
//! | 0 pend. Proposal  | ✅              | ✅              |
//! | 1+ pend. Proposal | ✅              | ✅              |

use openmls::framing::ProcessedMessage;
use openmls::prelude::MlsMessageOut;

use mls_crypto_provider::MlsCryptoProvider;

use crate::conversation::renew::Renew;
use crate::{ConversationId, CryptoError, CryptoResult, MlsCentral, MlsConversation, MlsError};

/// Represents the potential items a consumer might require after passing us an encrypted message we
/// have decrypted for him
#[derive(Debug)]
pub struct MlsConversationDecryptMessage {
    /// Decrypted text message
    pub app_msg: Option<Vec<u8>>,
    /// If decrypted message is a commit, this will contain either:
    /// * local pending proposal by value
    /// * proposals by value in pending commit
    pub proposals: Vec<MlsMessageOut>,
    /// Is the conversation still active after receiving this commit
    /// aka has the user been removed from the group
    pub is_active: bool,
    /// delay time to feed caller timer for committing
    pub delay: Option<u64>,
}

/// Abstraction over a MLS group capable of decrypting a MLS message
impl MlsConversation {
    /// see [MlsCentral::decrypt_message]
    pub async fn decrypt_message(
        &mut self,
        message: impl AsRef<[u8]>,
        backend: &MlsCryptoProvider,
    ) -> CryptoResult<MlsConversationDecryptMessage> {
        let msg_in = openmls::framing::MlsMessageIn::try_from_bytes(message.as_ref()).map_err(MlsError::from)?;

        let parsed_message = self.group.parse_message(msg_in, backend).map_err(MlsError::from)?;

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
            },
            ProcessedMessage::ProposalMessage(proposal) => {
                self.group.store_pending_proposal(*proposal);
                MlsConversationDecryptMessage {
                    app_msg: None,
                    proposals: vec![],
                    is_active: true,
                    delay: Some(self.compute_next_commit_delay()),
                }
            }
            ProcessedMessage::StagedCommitMessage(staged_commit) => {
                let pending_commit = self.group.pending_commit().cloned();
                #[allow(clippy::needless_collect)] // false positive
                let pending_proposals = self.group.pending_proposals().cloned().collect::<Vec<_>>();
                let valid_commit = staged_commit.clone();

                self.group.merge_staged_commit(*staged_commit).map_err(MlsError::from)?;

                let proposals = Renew::renew(
                    pending_proposals.into_iter(),
                    pending_commit.as_ref(),
                    valid_commit.as_ref(),
                );
                let proposals = self
                    .renew_proposals_for_current_epoch(backend, proposals.into_iter())
                    .await?;

                MlsConversationDecryptMessage {
                    app_msg: None,
                    proposals,
                    is_active: self.group.is_active(),
                    delay: None,
                }
            }
        };
        self.persist_group_when_changed(backend, false).await?;
        Ok(decrypted)
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
            .decrypt_message(message.as_ref(), &self.mls_backend)
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

    use crate::{
        credential::CredentialSupplier, proposal::MlsProposal, test_fixture_utils::*, test_utils::*,
        MlsConversationConfiguration,
    };

    use super::*;

    wasm_bindgen_test_configure!(run_in_browser);

    pub mod is_active {
        use super::*;

        #[apply(all_credential_types)]
        #[wasm_bindgen_test]
        pub async fn decrypting_a_regular_commit_should_leave_conversation_active(credential: CredentialSupplier) {
            run_test_with_client_ids(
                credential,
                ["alice", "bob"],
                move |[mut alice_central, mut bob_central]| {
                    Box::pin(async move {
                        let id = b"id".to_vec();
                        alice_central
                            .new_conversation(id.clone(), MlsConversationConfiguration::default())
                            .await
                            .unwrap();
                        let welcome = alice_central
                            .add_members_to_conversation(&id, &mut [bob_central.rnd_member().await])
                            .await
                            .unwrap()
                            .unwrap()
                            .welcome;
                        bob_central
                            .process_welcome_message(welcome, MlsConversationConfiguration::default())
                            .await
                            .unwrap();
                        alice_central.commit_accepted(&id).await.unwrap();

                        let (commit, _) = bob_central.update_keying_material(&id).await.unwrap();
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

        #[apply(all_credential_types)]
        #[wasm_bindgen_test]
        pub async fn decrypting_a_commit_removing_self_should_set_conversation_inactive(
            credential: CredentialSupplier,
        ) {
            run_test_with_client_ids(
                credential,
                ["alice", "bob"],
                move |[mut alice_central, mut bob_central]| {
                    Box::pin(async move {
                        let id = b"id".to_vec();
                        alice_central
                            .new_conversation(id.clone(), MlsConversationConfiguration::default())
                            .await
                            .unwrap();
                        let welcome = alice_central
                            .add_members_to_conversation(&id, &mut [bob_central.rnd_member().await])
                            .await
                            .unwrap()
                            .unwrap()
                            .welcome;
                        bob_central
                            .process_welcome_message(welcome, MlsConversationConfiguration::default())
                            .await
                            .unwrap();
                        alice_central.commit_accepted(&id).await.unwrap();

                        let commit = bob_central
                            .remove_members_from_conversation(&id, &[b"alice"[..].into()])
                            .await
                            .unwrap()
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

        #[apply(all_credential_types)]
        #[wasm_bindgen_test]
        pub async fn decrypting_a_commit_should_clear_pending_commit(credential: CredentialSupplier) {
            run_test_with_client_ids(
                credential,
                ["alice", "bob", "charlie", "debbie"],
                move |[mut alice_central, mut bob_central, charlie_central, debbie_central]| {
                    Box::pin(async move {
                        let id = b"id".to_vec();
                        alice_central
                            .new_conversation(id.clone(), MlsConversationConfiguration::default())
                            .await
                            .unwrap();
                        let welcome = alice_central
                            .add_members_to_conversation(&id, &mut [bob_central.rnd_member().await])
                            .await
                            .unwrap()
                            .unwrap()
                            .welcome;
                        bob_central
                            .process_welcome_message(welcome, MlsConversationConfiguration::default())
                            .await
                            .unwrap();
                        alice_central.commit_accepted(&id).await.unwrap();

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
                            .unwrap()
                            .message;
                        alice_central
                            .decrypt_message(&id, add_debbie_commit.to_bytes().unwrap())
                            .await
                            .unwrap();
                        // Now Debbie should be in members and not Charlie
                        assert!(alice_central[&id].members().get(&debbie.id).is_some());
                        assert!(alice_central[&id].members().get(&charlie.id).is_none());
                        // Previous commit to add Charlie has been discarded but its proposals will be renewed
                        assert!(alice_central.pending_commit(&id).is_none());
                    })
                },
            )
            .await
        }

        #[apply(all_credential_types)]
        #[wasm_bindgen_test]
        pub async fn decrypting_a_commit_should_renew_proposals_in_pending_commit(credential: CredentialSupplier) {
            run_test_with_client_ids(
                credential,
                ["alice", "bob", "charlie"],
                move |[mut alice_central, mut bob_central, mut charlie_central]| {
                    Box::pin(async move {
                        let id = b"id".to_vec();
                        alice_central
                            .new_conversation(id.clone(), MlsConversationConfiguration::default())
                            .await
                            .unwrap();
                        let welcome = alice_central
                            .add_members_to_conversation(&id, &mut [bob_central.rnd_member().await])
                            .await
                            .unwrap()
                            .unwrap()
                            .welcome;
                        bob_central
                            .process_welcome_message(welcome, MlsConversationConfiguration::default())
                            .await
                            .unwrap();
                        alice_central.commit_accepted(&id).await.unwrap();

                        // Alice will create a commit to add Charlie
                        // Bob will create a commit which will be accepted first by DS so Alice will decrypt it
                        // Then Alice will renew the proposal in her pending commit
                        let charlie = charlie_central.rnd_member().await;

                        let bob_commit = bob_central.update_keying_material(&id).await.unwrap().0;
                        bob_central.commit_accepted(&id).await.unwrap();
                        let commit_epoch = bob_commit.epoch();

                        // Alice propose to add Charlie
                        alice_central
                            .add_members_to_conversation(&id, &mut [charlie.clone()])
                            .await
                            .unwrap();
                        assert!(alice_central.pending_commit(&id).is_some());

                        // But first she receives Bob commit
                        let MlsConversationDecryptMessage { proposals, .. } = alice_central
                            .decrypt_message(&id, bob_commit.to_bytes().unwrap())
                            .await
                            .unwrap();
                        // So Charlie has not been added to the group
                        assert!(alice_central[&id].members().get(&charlie.id).is_none());

                        // But its proposal to add Charlie has been renewed and is also in store
                        assert!(!proposals.is_empty());
                        assert_eq!(alice_central.pending_proposals(&id).len(), 1);
                        assert!(alice_central.pending_commit(&id).is_none());
                        assert_eq!(commit_epoch.as_u64() + 1, proposals.first().unwrap().epoch().as_u64());

                        // Let's commit this proposal to see if it works
                        for p in proposals {
                            // But first, proposals have to be fan out to Bob
                            bob_central.decrypt_message(&id, p.to_bytes().unwrap()).await.unwrap();
                        }

                        let (commit, welcome) = alice_central.commit_pending_proposals(&id).await.unwrap();
                        alice_central.commit_accepted(&id).await.unwrap();
                        // Charlie is now in the group
                        assert!(alice_central[&id].members().get(&charlie.id).is_some());

                        bob_central
                            .decrypt_message(&id, commit.to_bytes().unwrap())
                            .await
                            .unwrap();
                        // Bob also has Charlie in the group
                        assert!(bob_central[&id].members().get(&charlie.id).is_some());

                        // Charlie can join with the Welcome from renewed Add proposal
                        let id = charlie_central
                            .process_welcome_message(welcome.unwrap(), MlsConversationConfiguration::default())
                            .await
                            .unwrap();
                        assert!(charlie_central.can_talk_to(&id, &mut alice_central).await.is_ok());
                    })
                },
            )
            .await
        }

        #[apply(all_credential_types)]
        #[wasm_bindgen_test]
        pub async fn decrypting_a_commit_should_not_renew_proposals_in_valid_commit(credential: CredentialSupplier) {
            run_test_with_client_ids(
                credential,
                ["alice", "bob", "charlie"],
                move |[mut alice_central, mut bob_central, charlie_central]| {
                    Box::pin(async move {
                        let id = b"id".to_vec();
                        alice_central
                            .new_conversation(id.clone(), MlsConversationConfiguration::default())
                            .await
                            .unwrap();
                        let welcome = alice_central
                            .add_members_to_conversation(&id, &mut [bob_central.rnd_member().await])
                            .await
                            .unwrap()
                            .unwrap()
                            .welcome;
                        bob_central
                            .process_welcome_message(welcome, MlsConversationConfiguration::default())
                            .await
                            .unwrap();
                        alice_central.commit_accepted(&id).await.unwrap();

                        // Bob will create a proposal to add Charlie
                        // Alice will decrypt this proposal
                        // Then Bob will create a commit to update
                        // Alice will decrypt the commit but musn't renew the proposal to add Charlie
                        let charlie_kp = charlie_central.get_one_key_package().await.unwrap();

                        let add_charlie_proposal = bob_central
                            .new_proposal(&id, MlsProposal::Add(charlie_kp))
                            .await
                            .unwrap();
                        alice_central
                            .decrypt_message(&id, add_charlie_proposal.to_bytes().unwrap())
                            .await
                            .unwrap();

                        let (commit, _) = bob_central.update_keying_material(&id).await.unwrap();
                        let MlsConversationDecryptMessage { proposals, .. } = alice_central
                            .decrypt_message(&id, commit.to_bytes().unwrap())
                            .await
                            .unwrap();
                        assert!(proposals.is_empty());
                        assert!(alice_central.pending_proposals(&id).is_empty());
                    })
                },
            )
            .await
        }

        // orphan proposal = not backed by the pending commit
        #[apply(all_credential_types)]
        #[wasm_bindgen_test]
        pub async fn decrypting_a_commit_should_renew_orphan_pending_proposals(credential: CredentialSupplier) {
            run_test_with_client_ids(
                credential,
                ["alice", "bob"],
                move |[mut alice_central, mut bob_central]| {
                    Box::pin(async move {
                        let id = b"id".to_vec();
                        alice_central
                            .new_conversation(id.clone(), MlsConversationConfiguration::default())
                            .await
                            .unwrap();
                        let welcome = alice_central
                            .add_members_to_conversation(&id, &mut [bob_central.rnd_member().await])
                            .await
                            .unwrap()
                            .unwrap()
                            .welcome;
                        bob_central
                            .process_welcome_message(welcome, MlsConversationConfiguration::default())
                            .await
                            .unwrap();
                        alice_central.commit_accepted(&id).await.unwrap();

                        // Alice will create a proposal to add Charlie
                        // Bob will create a commit which Alice will decrypt
                        // Then Alice will renew her proposal
                        let (_, charlie) = charlie(credential).await.unwrap();
                        let bob_commit = bob_central.update_keying_material(&id).await.unwrap().0;
                        bob_central.commit_accepted(&id).await.unwrap();
                        let commit_epoch = bob_commit.epoch();
                        let backend = &alice_central.mls_backend;
                        let charlie_kp = charlie
                            .local_client
                            .as_ref()
                            .unwrap()
                            .gen_keypackage(backend)
                            .await
                            .unwrap()
                            .key_package()
                            .clone();

                        // Alice propose to add Charlie
                        alice_central
                            .new_proposal(&id, MlsProposal::Add(charlie_kp))
                            .await
                            .unwrap();
                        assert_eq!(alice_central.pending_proposals(&id).len(), 1);

                        // But first she receives Bob commit
                        let MlsConversationDecryptMessage { proposals, .. } = alice_central
                            .decrypt_message(&id, bob_commit.to_bytes().unwrap())
                            .await
                            .unwrap();
                        // So Charlie has not been added to the group
                        assert!(alice_central[&id].members().get(&charlie.id).is_none());

                        // But its proposal to add Charlie has been renewed and is also in store
                        assert!(!proposals.is_empty());
                        assert_eq!(alice_central.pending_proposals(&id).len(), 1);
                        let renewed_proposal = proposals.first().unwrap();
                        assert_eq!(commit_epoch.as_u64() + 1, renewed_proposal.epoch().as_u64());

                        // Let's use this proposal to see if it works
                        bob_central
                            .decrypt_message(&id, renewed_proposal.to_bytes().unwrap())
                            .await
                            .unwrap();
                        assert_eq!(bob_central.pending_proposals(&id).len(), 1);
                        let (commit, _) = bob_central.commit_pending_proposals(&id).await.unwrap();
                        alice_central
                            .decrypt_message(&id, commit.to_bytes().unwrap())
                            .await
                            .unwrap();
                        // Charlie is now in the group
                        assert!(alice_central[&id].members().get(&charlie.id).is_some());

                        // Bob also has Charlie in the group
                        bob_central.commit_accepted(&id).await.unwrap();
                        assert!(bob_central[&id].members().get(&charlie.id).is_some());
                    })
                },
            )
            .await
        }

        #[apply(all_credential_types)]
        #[wasm_bindgen_test]
        pub async fn decrypting_a_commit_should_discard_pending_external_proposals(credential: CredentialSupplier) {
            run_test_with_client_ids(
                credential,
                ["alice", "bob", "charlie"],
                move |[mut alice_central, mut bob_central, charlie_central]| {
                    Box::pin(async move {
                        let id = b"id".to_vec();
                        alice_central
                            .new_conversation(id.clone(), MlsConversationConfiguration::default())
                            .await
                            .unwrap();
                        let welcome = alice_central
                            .add_members_to_conversation(&id, &mut [bob_central.rnd_member().await])
                            .await
                            .unwrap()
                            .unwrap()
                            .welcome;
                        alice_central.commit_accepted(&id).await.unwrap();
                        bob_central
                            .process_welcome_message(welcome, MlsConversationConfiguration::default())
                            .await
                            .unwrap();

                        // DS will create an external proposal to add Charlie
                        // But meanwhile Bob, before receiving the external proposal,
                        // will create a commit and send it to Alice.
                        // Alice will not renew the external proposal
                        let charlie_kp = charlie_central.get_one_key_package().await.unwrap();
                        let ext_proposal = charlie_central
                            .new_external_add_proposal(id.clone(), alice_central[&id].group.epoch(), charlie_kp)
                            .await
                            .unwrap();
                        assert!(alice_central.pending_proposals(&id).is_empty());
                        alice_central
                            .decrypt_message(&id, ext_proposal.to_bytes().unwrap())
                            .await
                            .unwrap();
                        assert_eq!(alice_central.pending_proposals(&id).len(), 1);

                        let commit = bob_central.update_keying_material(&id).await.unwrap().0;
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
    }
}
