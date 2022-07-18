//! Handshake refers here to either a commit or proposal message. Overall, it covers all the
//! operation modifying the group state
//!
//! This table summarizes when a MLS group can create a commit or proposal:
//!
//! | can create handshake ? | 0 pend. Commit | 1 pend. Commit |
//! |------------------------|----------------|----------------|
//! | 0 pend. Proposal       | ✅              | ❌              |
//! | 1+ pend. Proposal      | ✅              | ❌              |

use openmls::prelude::{hash_ref::HashReference, KeyPackage, KeyPackageRef, MlsMessageOut, Welcome};
use openmls_traits::OpenMlsCryptoProvider;

use mls_crypto_provider::MlsCryptoProvider;

use crate::{member::ConversationMember, ClientId, ConversationId, CryptoError, CryptoResult, MlsCentral, MlsError};

use super::MlsConversation;

/// Returned when initializing a conversation. Different from conversation created from a [`Welcome`] message or an external commit.
#[derive(Debug)]
pub struct MlsConversationCreationMessage {
    /// A welcome message indicating new members were added by a commit
    pub welcome: Welcome,
    /// A message that will contain information about the last commit
    pub message: MlsMessageOut,
}

impl MlsConversationCreationMessage {
    /// Serializes both wrapped objects into TLS and return them as a tuple of byte arrays.
    /// 0 -> welcome
    /// 1 -> message
    pub fn to_bytes_pairs(&self) -> CryptoResult<(Vec<u8>, Vec<u8>)> {
        use openmls::prelude::TlsSerializeTrait as _;
        let welcome = self.welcome.tls_serialize_detached().map_err(MlsError::from)?;

        let msg = self.message.to_bytes().map_err(MlsError::from)?;

        Ok((welcome, msg))
    }
}

/// It is a wrapper for the self removal proposal and a message containing a commit with the
/// removal of other clients. It is returned when calling [crate::MlsCentral::leave_conversation]
#[derive(Debug)]
pub struct MlsConversationLeaveMessage {
    /// A message containing information about the last commit
    pub self_removal_proposal: MlsMessageOut,
    /// Optional message when other clients were also removed from the group
    pub other_clients_removal_commit: Option<MlsMessageOut>,
}

/// Abstraction over a MLS group capable of creating proposal/commit messages
#[derive(Debug, derive_more::Deref, derive_more::DerefMut)]
pub struct MlsConversationCanHandshake<'a>(&'a mut MlsConversation);

/// Creating proposals
impl MlsConversationCanHandshake<'_> {
    /// see [openmls::group::MlsGroup::propose_add_member]
    pub async fn propose_add_member(
        &mut self,
        backend: &MlsCryptoProvider,
        key_package: &KeyPackage,
    ) -> CryptoResult<MlsMessageOut> {
        Ok(self
            .group
            .propose_add_member(backend, key_package)
            .await
            .map_err(MlsError::from)?)
    }

    /// see [openmls::group::MlsGroup::propose_self_update]
    pub async fn propose_self_update(&mut self, backend: &MlsCryptoProvider) -> CryptoResult<MlsMessageOut> {
        Ok(self
            .group
            .propose_self_update(backend, None)
            .await
            .map_err(MlsError::from)?)
    }

    /// see [openmls::group::MlsGroup::propose_remove_member]
    pub async fn propose_remove_member(
        &mut self,
        backend: &MlsCryptoProvider,
        member: &KeyPackageRef,
    ) -> CryptoResult<MlsMessageOut> {
        Ok(self
            .group
            .propose_remove_member(backend, member)
            .await
            .map_err(MlsError::from)?)
    }
}

/// Creating commit
impl MlsConversationCanHandshake<'_> {
    const REASON: &'static str = "Cannot create a commit or a proposal when there is a pending commit in the group";

    /// see [MlsCentral::add_members_to_conversation]
    /// Note: this is not exposed publicly because authorization isn't handled at this level
    pub async fn add_members(
        &mut self,
        members: &mut [ConversationMember],
        backend: &MlsCryptoProvider,
    ) -> CryptoResult<MlsConversationCreationMessage> {
        let keypackages = members
            .iter_mut()
            .flat_map(|member| member.keypackages_for_all_clients())
            .filter_map(|(_, kps)| kps)
            .collect::<Vec<KeyPackage>>();

        let (message, welcome) = self
            .group
            .add_members(backend, &keypackages)
            .await
            .map_err(MlsError::from)?;

        Ok(MlsConversationCreationMessage { welcome, message })
    }

    /// see [MlsCentral::remove_members_from_conversation]
    /// Note: this is not exposed publicly because authorization isn't handled at this level
    pub(crate) async fn remove_members(
        &mut self,
        clients: &[ClientId],
        backend: &MlsCryptoProvider,
    ) -> CryptoResult<MlsMessageOut> {
        let crypto = backend.crypto();

        let member_kps = self
            .group
            .members()
            .into_iter()
            .filter(|kp| {
                clients
                    .iter()
                    .any(move |client_id| client_id.as_slice() == kp.credential().identity())
            })
            .try_fold(Vec::new(), |mut acc, kp| -> CryptoResult<Vec<KeyPackageRef>> {
                acc.push(kp.hash_ref(crypto).map_err(MlsError::from)?);
                Ok(acc)
            })?;

        let (message, _) = self
            .group
            .remove_members(backend, &member_kps)
            .await
            .map_err(MlsError::from)?;

        Ok(message)
    }

    /// see [MlsCentral::leave_conversation]
    pub(crate) async fn leave(
        &mut self,
        other_clients: &[ClientId],
        backend: &MlsCryptoProvider,
    ) -> CryptoResult<MlsConversationLeaveMessage> {
        let crypto = backend.crypto();

        let (self_removal_proposal, other_clients_removal_commit) = if !other_clients.is_empty() {
            let other_clients_slice = other_clients.iter().map(|c| c.as_slice()).collect::<Vec<&[u8]>>();
            let members = self.0.group.members();
            let members_to_remove = members
                .into_iter()
                .filter(|m| other_clients_slice.contains(&m.credential().identity()))
                .filter_map(|m| m.hash_ref(crypto).ok())
                .collect::<Vec<HashReference>>();
            let (self_removal_proposal, other_clients_removal_commit) = self
                .group
                .leave_group_and_remove_others(backend, &members_to_remove)
                .await
                .map_err(MlsError::from)?;
            (self_removal_proposal, Some(other_clients_removal_commit))
        } else {
            let self_removal_proposal = self.0.group.leave_group(backend).await.map_err(MlsError::from)?;
            (self_removal_proposal, None)
        };
        Ok(MlsConversationLeaveMessage {
            other_clients_removal_commit,
            self_removal_proposal,
        })
    }

    /// see [MlsCentral::update_keying_material]
    pub async fn update_keying_material(
        &mut self,
        backend: &MlsCryptoProvider,
    ) -> CryptoResult<(MlsMessageOut, Option<Welcome>)> {
        Ok(self.group.self_update(backend, None).await.map_err(MlsError::from)?)
    }

    /// see [MlsCentral::commit_pending_proposals]
    pub async fn commit_pending_proposals(
        &mut self,
        backend: &MlsCryptoProvider,
    ) -> CryptoResult<(MlsMessageOut, Option<Welcome>)> {
        let (message, welcome) = self
            .group
            .commit_to_pending_proposals(backend)
            .await
            .map_err(MlsError::from)?;

        Ok((message, welcome))
    }
}

impl<'a> TryFrom<&'a mut MlsConversation> for MlsConversationCanHandshake<'a> {
    type Error = CryptoError;

    fn try_from(conv: &'a mut MlsConversation) -> CryptoResult<Self> {
        if conv.group.pending_commit().is_none() {
            Ok(Self(conv))
        } else {
            Err(CryptoError::GroupStateError(Self::REASON))
        }
    }
}

impl MlsCentral {
    /// Adds new members to the group/conversation
    ///
    /// # Arguments
    /// * `id` - group/conversation id
    /// * `members` - members to be added to the group
    ///
    /// # Return type
    /// An optional struct containing a welcome and a message will be returned on successful call.
    /// The value will be `None` only if the group can't be found locally (no error will be returned
    /// in this case).
    ///
    /// # Errors
    /// If the authorisation callback is set, an error can be caused when the authorization fails.
    /// Other errors are KeyStore and OpenMls errors:
    pub async fn add_members_to_conversation(
        &mut self,
        id: &ConversationId,
        members: &mut [ConversationMember],
    ) -> CryptoResult<Option<MlsConversationCreationMessage>> {
        if let Some(callbacks) = self.callbacks.as_ref() {
            if !callbacks.authorize(id.clone(), self.mls_client.id().to_string()) {
                return Err(CryptoError::Unauthorized);
            }
        }
        // TODO: Change method signature to 'CryptoResult<MlsConversationCreationMessage>'. It should fail when conversation not found
        if let Ok(mut group) = Self::get_conversation_mut::<MlsConversationCanHandshake>(&mut self.mls_groups, id) {
            Ok(Some(group.add_members(members, &self.mls_backend).await?))
        } else {
            Ok(None)
        }
    }

    /// Removes clients from the group/conversation.
    ///
    /// # Arguments
    /// * `id` - group/conversation id
    /// * `clients` - list of client ids to be removed from the group
    ///
    /// # Return type
    /// An optional message will be returned on successful call.
    /// The value will be `None` only if the group can't be found locally (no error will be returned
    /// in this case).
    ///
    /// # Errors
    /// If the authorisation callback is set, an error can be caused when the authorization fails. Other errors are KeyStore and OpenMls errors.
    pub async fn remove_members_from_conversation(
        &mut self,
        id: &ConversationId,
        clients: &[ClientId],
    ) -> CryptoResult<Option<MlsMessageOut>> {
        if let Some(callbacks) = self.callbacks.as_ref() {
            if !callbacks.authorize(id.clone(), self.mls_client.id().to_string()) {
                return Err(CryptoError::Unauthorized);
            }
        }

        // TODO: Change method signature to 'CryptoResult<MlsMessageOut>'. It should fail when conversation not found
        if let Ok(mut group) = Self::get_conversation_mut::<MlsConversationCanHandshake>(&mut self.mls_groups, id) {
            Ok(Some(group.remove_members(clients, &self.mls_backend).await?))
        } else {
            Ok(None)
        }
    }

    /// Leaves a conversation and provided other clients of the current user
    /// If the list of other clients is not empty, this will generate a commit to remove the other
    /// clietns.
    ///
    /// # Arguments
    /// * `id` - group/conversation id
    /// * `other_clients` - list of other client ids from the user to be removed from the group
    ///
    /// # Return type
    /// A struct containing an optional message for the commit of the removal of the other clients
    /// and a message containing the proposal to remove the local client.
    ///
    /// # Errors
    /// If the conversation can't be found, an error will be returned. Other errors are originating
    /// from OpenMls and the KeyStore
    pub async fn leave_conversation(
        &mut self,
        conversation: &ConversationId,
        other_clients: &[ClientId],
    ) -> CryptoResult<MlsConversationLeaveMessage> {
        let messages = if let Ok(mut group) =
            Self::get_conversation_mut::<MlsConversationCanHandshake>(&mut self.mls_groups, conversation)
        {
            group.leave(other_clients, &self.mls_backend).await?
        } else {
            return Err(CryptoError::ConversationNotFound(conversation.clone()));
        };

        // TODO: this should be done on "commit_accepted"
        // let _ = self.mls_groups.remove(conversation.as_slice());
        Ok(messages)
    }

    /// Self updates the KeyPackage and automatically commits. Pending proposals will be commited
    ///
    /// # Arguments
    /// * `conversation_id` - the group/conversation id
    ///
    /// # Return type
    /// A tuple containing the message with the commit this call generated and an optional welcome
    /// message that will be present if there were pending add proposals to be commited
    ///
    /// # Errors
    /// If the conversation can't be found, an error will be returned. Other errors are originating
    /// from OpenMls and the KeyStore
    pub async fn update_keying_material(
        &mut self,
        conversation_id: &ConversationId,
    ) -> CryptoResult<(MlsMessageOut, Option<Welcome>)> {
        Self::get_conversation_mut::<MlsConversationCanHandshake>(&mut self.mls_groups, conversation_id)?
            .update_keying_material(&self.mls_backend)
            .await
    }

    /// Commits all pending proposals of the group
    ///
    /// # Arguments
    /// * `backend` - the KeyStore to persist group changes
    ///
    /// # Return type
    /// A tuple containing the commit message and a possible welcome (in the case `Add` proposals were pending within the internal MLS Group)
    ///
    /// # Errors
    /// Errors can be originating from the KeyStore and OpenMls
    pub async fn commit_pending_proposals(
        &mut self,
        conversation: &ConversationId,
    ) -> CryptoResult<(MlsMessageOut, Option<Welcome>)> {
        Self::get_conversation_mut::<MlsConversationCanHandshake>(&mut self.mls_groups, conversation)?
            .commit_pending_proposals(&self.mls_backend)
            .await
    }
}

#[cfg(test)]
impl MlsConversation {
    pub fn as_can_handshake(&mut self) -> MlsConversationCanHandshake {
        MlsConversationCanHandshake::try_from(self).unwrap()
    }
}

#[cfg(test)]
pub mod tests {
    use openmls::prelude::{KeyPackage, LeaveGroupError};
    use wasm_bindgen_test::*;

    use crate::{
        credential::CredentialSupplier, test_fixture_utils::*, test_utils::*, MlsCentral, MlsConversationConfiguration,
    };

    use super::super::state_tests_utils::*;
    use super::*;

    wasm_bindgen_test_configure!(run_in_browser);

    pub mod state {
        use super::*;

        #[apply(all_credential_types)]
        #[wasm_bindgen_test]
        pub async fn can_handshake_when_no_pending(credential: CredentialSupplier) {
            run_test_with_central(credential, move |[mut central]| {
                Box::pin(async move {
                    let id = b"id".to_vec();
                    conv_no_pending(&mut central, &id).await;
                    let can_handshake =
                        MlsCentral::get_conversation_mut::<MlsConversationCanHandshake>(&mut central.mls_groups, &id);
                    assert!(can_handshake.is_ok());
                })
            })
            .await
        }

        #[apply(all_credential_types)]
        #[wasm_bindgen_test]
        pub async fn can_handshake_when_pending_proposals_and_no_pending_commit(credential: CredentialSupplier) {
            run_test_with_central(credential, move |[mut central]| {
                Box::pin(async move {
                    let id = b"id".to_vec();
                    conv_pending_proposal_and_no_pending_commit(&mut central, &id).await;
                    let can_handshake =
                        MlsCentral::get_conversation_mut::<MlsConversationCanHandshake>(&mut central.mls_groups, &id);
                    assert!(can_handshake.is_ok());
                })
            })
            .await
        }

        #[apply(all_credential_types)]
        #[wasm_bindgen_test]
        pub async fn cannot_handshake_when_no_pending_proposals_and_pending_commit(credential: CredentialSupplier) {
            run_test_with_central(credential, move |[mut central]| {
                Box::pin(async move {
                    let id = b"id".to_vec();
                    conv_no_pending_proposal_and_pending_commit(&mut central, &id).await;
                    let can_handshake =
                        MlsCentral::get_conversation_mut::<MlsConversationCanHandshake>(&mut central.mls_groups, &id);
                    assert!(matches!(
                        can_handshake.unwrap_err(),
                        CryptoError::GroupStateError(MlsConversationCanHandshake::REASON)
                    ));
                })
            })
            .await
        }

        #[apply(all_credential_types)]
        #[wasm_bindgen_test]
        pub async fn cannot_handshake_when_pending_proposals_and_pending_commit(credential: CredentialSupplier) {
            run_test_with_client_ids(credential, ["alice", "bob"], move |[mut alice_central, bob_central]| {
                Box::pin(async move {
                    let id = b"id".to_vec();
                    conv_pending_proposal_and_pending_commit(&mut alice_central, bob_central, &id).await;
                    let can_handshake = MlsCentral::get_conversation_mut::<MlsConversationCanHandshake>(
                        &mut alice_central.mls_groups,
                        &id,
                    );
                    assert!(matches!(
                        can_handshake.unwrap_err(),
                        CryptoError::GroupStateError(MlsConversationCanHandshake::REASON)
                    ));
                })
            })
            .await
        }
    }

    pub mod add_members {
        use super::*;

        #[apply(all_credential_types)]
        #[wasm_bindgen_test]
        pub async fn can_add_members_to_conversation(credential: CredentialSupplier) {
            let conversation_id = conversation_id();
            let (alice_backend, mut alice) = alice(credential).await.unwrap();
            let (bob_backend, bob) = bob(credential).await.unwrap();

            let conversation_config = MlsConversationConfiguration::default();
            let mut alice_group = MlsConversation::create(
                conversation_id.clone(),
                alice.local_client_mut(),
                conversation_config,
                &alice_backend,
            )
            .await
            .unwrap();

            let conversation_creation_message = alice_group
                .as_can_handshake()
                .add_members(&mut [bob], &alice_backend)
                .await
                .unwrap();

            // before merging, commit is not applied
            assert_eq!(alice_group.members().len(), 1);
            alice_group
                .as_can_merge()
                .commit_accepted(&alice_backend)
                .await
                .unwrap();

            assert_eq!(alice_group.id, conversation_id);
            assert_eq!(alice_group.group.group_id().as_slice(), conversation_id);
            assert_eq!(alice_group.members().len(), 2);

            let MlsConversationCreationMessage { welcome, .. } = conversation_creation_message;

            let conversation_config = MlsConversationConfiguration::default();

            let mut bob_group = MlsConversation::from_welcome_message(welcome, conversation_config, &bob_backend)
                .await
                .unwrap();

            assert_eq!(bob_group.id(), alice_group.id());

            let msg = b"Hello";
            let alice_can_send_message = alice_group.as_can_encrypt().encrypt_message(msg, &alice_backend).await;
            assert!(alice_can_send_message.is_ok());
            let bob_can_send_message = bob_group.as_can_encrypt().encrypt_message(msg, &bob_backend).await;
            assert!(bob_can_send_message.is_ok());
        }
    }

    pub mod remove_members {
        use super::*;

        #[apply(all_credential_types)]
        #[wasm_bindgen_test]
        pub async fn alice_can_remove_bob_from_conversation(credential: CredentialSupplier) {
            let conversation_id = conversation_id();
            let (alice_backend, mut alice) = alice(credential).await.unwrap();
            let (bob_backend, bob) = bob(credential).await.unwrap();

            let conversation_config = MlsConversationConfiguration::default();

            let mut alice_group = MlsConversation::create(
                conversation_id,
                alice.local_client_mut(),
                conversation_config,
                &alice_backend,
            )
            .await
            .unwrap();

            let messages = alice_group
                .as_can_handshake()
                .add_members(&mut [bob.clone()], &alice_backend)
                .await
                .unwrap();
            alice_group
                .as_can_merge()
                .commit_accepted(&alice_backend)
                .await
                .unwrap();

            assert_eq!(alice_group.members().len(), 2);

            let mut bob_group = MlsConversation::from_welcome_message(
                messages.welcome,
                MlsConversationConfiguration::default(),
                &bob_backend,
            )
            .await
            .unwrap();

            let remove_result = alice_group
                .as_can_handshake()
                .remove_members(bob.clients().cloned().collect::<Vec<_>>().as_slice(), &alice_backend)
                .await
                .unwrap();
            // before merging, commit is not applied
            assert_eq!(alice_group.members().len(), 2);
            alice_group
                .as_can_merge()
                .commit_accepted(&alice_backend)
                .await
                .unwrap();

            bob_group
                .as_can_decrypt()
                .decrypt_message(remove_result.to_bytes().unwrap(), &bob_backend)
                .await
                .unwrap();

            assert_eq!(alice_group.members().len(), 1);

            let alice_can_send_message = alice_group
                .as_can_encrypt()
                .encrypt_message(b"me", &alice_backend)
                .await;
            assert!(alice_can_send_message.is_ok());
            let bob_cannot_send_message = alice_group.as_can_encrypt().encrypt_message(b"me", &bob_backend).await;
            assert!(bob_cannot_send_message.is_err());
        }
    }

    pub mod leave {
        use super::*;

        #[apply(all_credential_types)]
        #[wasm_bindgen_test]
        pub async fn can_leave_conversation(credential: CredentialSupplier) {
            run_test_with_client_ids(
                credential,
                ["alice1", "alice2", "bob", "charlie"],
                move |[mut alice1_central, mut alice2_central, mut bob_central, mut charlie_central]| {
                    Box::pin(async move {
                        let conv_id = b"id".to_vec();

                        let alice2 = ConversationMember::random_generate(&alice2_central.mls_backend, credential)
                            .await
                            .unwrap();
                        let bob = ConversationMember::random_generate(&bob_central.mls_backend, credential)
                            .await
                            .unwrap();
                        let charlie = ConversationMember::random_generate(&charlie_central.mls_backend, credential)
                            .await
                            .unwrap();

                        let conversation_config = MlsConversationConfiguration::default();
                        alice1_central
                            .new_conversation(conv_id.clone(), conversation_config.clone())
                            .await
                            .unwrap();
                        let conversation_creation_message = alice1_central
                            .add_members_to_conversation(&conv_id, &mut [alice2, bob, charlie])
                            .await
                            .unwrap()
                            .unwrap();
                        alice1_central.commit_accepted(&conv_id).await.unwrap();

                        assert_eq!(alice1_central.get_conversation(&conv_id).unwrap().members().len(), 4);

                        let MlsConversationCreationMessage { welcome, .. } = conversation_creation_message;

                        bob_central
                            .process_welcome_message(welcome.clone(), conversation_config.clone())
                            .await
                            .unwrap();
                        charlie_central
                            .process_welcome_message(welcome.clone(), conversation_config.clone())
                            .await
                            .unwrap();
                        alice2_central
                            .process_welcome_message(welcome.clone(), conversation_config.clone())
                            .await
                            .unwrap();

                        assert_eq!(alice2_central.get_conversation(&conv_id).unwrap().members().len(), 4);
                        assert_eq!(bob_central.get_conversation(&conv_id).unwrap().members().len(), 4);
                        assert_eq!(charlie_central.get_conversation(&conv_id).unwrap().members().len(), 4);

                        // Alice2 wants to leave. This will produce:
                        // - a commit with inline remove proposal for Alice1
                        // - a remove proposal for Alice2 signed for epoch + 1
                        // let alice1_id = alice2_central.get_conversation(&conv_id).unwrap()

                        let MlsConversationLeaveMessage {
                            self_removal_proposal: remove_proposal_alice2,
                            other_clients_removal_commit: remove_commit_alice1,
                        } = alice2_central
                            .leave_conversation(&conv_id, &[alice1_central.client_id()])
                            .await
                            .unwrap();
                        let remove_commit_alice1 = remove_commit_alice1.unwrap();

                        // before merging, commit is not applied
                        assert_eq!(alice2_central.get_conversation(&conv_id).unwrap().members().len(), 4);

                        // remove proposal for the client who initiated the leave must be after the commit
                        // removing other clients
                        assert_eq!(
                            remove_commit_alice1.epoch().as_u64() + 1,
                            remove_proposal_alice2.epoch().as_u64()
                        );

                        alice2_central.commit_accepted(&conv_id).await.unwrap();

                        // Only the `other_clients` have been effectively removed as of now
                        // Removing alice2 will only be effective once bob or charlie commit the removal proposal that alice2 leaves
                        assert_eq!(alice2_central.get_conversation(&conv_id).unwrap().members().len(), 3);

                        // Now other clients receive the commit to remove Alice1
                        bob_central
                            .decrypt_message(&conv_id, remove_commit_alice1.to_bytes().unwrap())
                            .await
                            .unwrap();
                        charlie_central
                            .decrypt_message(&conv_id, remove_commit_alice1.to_bytes().unwrap())
                            .await
                            .unwrap();

                        assert_eq!(bob_central.get_conversation(&conv_id).unwrap().members().len(), 3);
                        assert_eq!(charlie_central.get_conversation(&conv_id).unwrap().members().len(), 3);

                        alice1_central
                            .decrypt_message(&conv_id, remove_commit_alice1.to_bytes().unwrap())
                            .await
                            .unwrap();
                        // alice_group is now unuseable
                        assert!(alice1_central.encrypt_message(&conv_id, b"test").await.is_err());
                        assert!(matches!(
                            alice1_central.get_conversation(&conv_id).unwrap_err(),
                            CryptoError::ConversationNotFound(id) if conv_id == id
                        ));

                        // And now Bob & Charlie receives the proposal to remove Alice2
                        bob_central
                            .decrypt_message(&conv_id, remove_proposal_alice2.to_bytes().unwrap())
                            .await
                            .unwrap();
                        charlie_central
                            .decrypt_message(&conv_id, remove_proposal_alice2.to_bytes().unwrap())
                            .await
                            .unwrap();

                        // Bob decides to commit this proposal
                        let (removal_commit_from_bob, _) =
                            bob_central.commit_pending_proposals(&conv_id).await.unwrap();
                        bob_central.commit_accepted(&conv_id).await.unwrap();
                        assert_eq!(bob_central.get_conversation(&conv_id).unwrap().members().len(), 2);

                        charlie_central
                            .decrypt_message(&conv_id, removal_commit_from_bob.to_bytes().unwrap())
                            .await
                            .unwrap();
                        assert_eq!(charlie_central.get_conversation(&conv_id).unwrap().members().len(), 2);

                        alice2_central
                            .decrypt_message(&conv_id, removal_commit_from_bob.to_bytes().unwrap())
                            .await
                            .unwrap();
                        // Check that alice2 conversation is gone
                        assert!(matches!(
                            alice2_central.get_conversation(&conv_id).unwrap_err(),
                            CryptoError::ConversationNotFound(id) if conv_id == id
                        ));
                    })
                },
            )
            .await;
        }

        #[apply(all_credential_types)]
        #[wasm_bindgen_test]
        pub async fn can_just_leave_self(credential: CredentialSupplier) {
            run_test_with_client_ids(
                credential,
                ["alice", "bob"],
                move |[mut alice_central, mut bob_central]| {
                    Box::pin(async move {
                        let conv_id = b"id".to_vec();

                        let bob = ConversationMember::random_generate(&bob_central.mls_backend, credential)
                            .await
                            .unwrap();

                        let conversation_config = MlsConversationConfiguration::default();
                        alice_central
                            .new_conversation(conv_id.clone(), conversation_config.clone())
                            .await
                            .unwrap();
                        let conversation_creation_message = alice_central
                            .add_members_to_conversation(&conv_id, &mut [bob])
                            .await
                            .unwrap()
                            .unwrap();
                        alice_central.commit_accepted(&conv_id).await.unwrap();

                        assert_eq!(alice_central.get_conversation(&conv_id).unwrap().members().len(), 2);

                        let MlsConversationCreationMessage { welcome, .. } = conversation_creation_message;

                        bob_central
                            .process_welcome_message(welcome.clone(), conversation_config.clone())
                            .await
                            .unwrap();

                        assert_eq!(bob_central.get_conversation(&conv_id).unwrap().members().len(), 2);

                        // Alice just wants to leave
                        let MlsConversationLeaveMessage {
                            self_removal_proposal: remove_proposal_alice,
                            other_clients_removal_commit: remove_commit,
                        } = alice_central.leave_conversation(&conv_id, &[]).await.unwrap();
                        assert!(remove_commit.is_none());

                        // Now Bob receive the proposal to remove Alice and decides to commit it
                        bob_central
                            .decrypt_message(&conv_id, remove_proposal_alice.to_bytes().unwrap())
                            .await
                            .unwrap();
                        let (removal_commit_from_bob, _) =
                            bob_central.commit_pending_proposals(&conv_id).await.unwrap();
                        bob_central.commit_accepted(&conv_id).await.unwrap();
                        assert_eq!(bob_central.get_conversation(&conv_id).unwrap().members().len(), 1);

                        alice_central
                            .decrypt_message(&conv_id, removal_commit_from_bob.to_bytes().unwrap())
                            .await
                            .unwrap();
                        // Check that alice conversation is gone
                        assert!(matches!(
                            alice_central.get_conversation(&conv_id).unwrap_err(),
                            CryptoError::ConversationNotFound(id) if conv_id == id
                        ));
                    })
                },
            )
            .await;
        }

        #[apply(all_credential_types)]
        #[wasm_bindgen_test]
        pub async fn cannot_commit_leave_self(credential: CredentialSupplier) {
            run_test_with_central(credential, move |[mut alice_central]| {
                Box::pin(async move {
                    let id = b"id".to_vec();
                    alice_central
                        .new_conversation(id.clone(), MlsConversationConfiguration::default())
                        .await
                        .unwrap();
                    let leave_self = alice_central
                        .leave_conversation(&id, &[alice_central.client_id()])
                        .await;

                    assert!(matches!(
                        leave_self.unwrap_err(),
                        CryptoError::MlsError(MlsError::MlsLeaveGroupError(LeaveGroupError::AttemptToRemoveSelf))
                    ));
                })
            })
            .await;
        }
    }

    pub mod update_keying_material {
        use super::*;

        #[apply(all_credential_types)]
        #[wasm_bindgen_test]
        pub async fn should_update_keying_material_conversation_group(credential: CredentialSupplier) {
            // create bob
            let conversation_id = b"conversation".to_vec();
            let (alice_backend, mut alice) = alice(credential).await.unwrap();
            let (bob_backend, bob) = bob(credential).await.unwrap();

            let bob_key = bob.local_client().keypackages(&bob_backend).await.unwrap()[0].clone();

            let configuration = MlsConversationConfiguration::default();

            // create new group and add bob
            let mut alice_group = MlsConversation::create(
                conversation_id,
                alice.local_client_mut(),
                configuration.clone(),
                &alice_backend,
            )
            .await
            .unwrap();

            let add_message = alice_group
                .as_can_handshake()
                .add_members(&mut [bob], &alice_backend)
                .await
                .unwrap();
            alice_group
                .as_can_merge()
                .commit_accepted(&alice_backend)
                .await
                .unwrap();

            assert_eq!(alice_group.members().len(), 2);

            let MlsConversationCreationMessage { welcome, .. } = add_message;

            // creating group on bob's side
            let mut bob_group = MlsConversation::from_welcome_message(welcome, configuration, &bob_backend)
                .await
                .unwrap();

            // ensuring both sides can encrypt messages
            let msg = b"Hello";
            let alice_can_send_message = alice_group.as_can_encrypt().encrypt_message(msg, &alice_backend).await;
            assert!(alice_can_send_message.is_ok());
            let bob_can_send_message = bob_group.as_can_encrypt().encrypt_message(msg, &bob_backend).await;
            assert!(bob_can_send_message.is_ok());

            let bob_keys = bob_group.group.members();
            let alice_keys = alice_group.group.members();
            assert!(alice_keys.iter().all(|a_key| bob_keys.contains(a_key)));

            let alice_key = alice_keys.into_iter().find(|&k| *k != bob_key).unwrap().clone();
            // proposing the key update for alice
            let (msg_out, welcome) = alice_group
                .as_can_handshake()
                .update_keying_material(&alice_backend)
                .await
                .unwrap();
            assert!(welcome.is_none());

            // before merging, commit is not applied
            assert!(alice_group.group.members().contains(&&alice_key));
            alice_group
                .as_can_merge()
                .commit_accepted(&alice_backend)
                .await
                .unwrap();

            let alice_new_keys = alice_group.group.members();
            assert!(!alice_new_keys.contains(&&alice_key));

            // receiving the commit on bob's side (updating key from alice)
            assert!(bob_group
                .as_can_decrypt()
                .decrypt_message(&msg_out.to_bytes().unwrap(), &bob_backend)
                .await
                .unwrap()
                .0
                .is_none());

            let bob_new_keys = bob_group
                .group
                .members()
                .into_iter()
                .cloned()
                .collect::<Vec<KeyPackage>>();

            assert!(alice_new_keys.iter().all(|a_key| bob_new_keys.contains(a_key)));

            // ensuring both can encrypt messages
            let bob_can_send_message = bob_group.as_can_encrypt().encrypt_message(msg, &bob_backend).await;
            assert!(bob_can_send_message.is_ok());

            let alice_can_send_message = alice_group.as_can_encrypt().encrypt_message(msg, &alice_backend).await;
            assert!(alice_can_send_message.is_ok());
        }

        #[apply(all_credential_types)]
        #[wasm_bindgen_test]
        pub async fn should_update_keying_material_group_pending_commit(credential: CredentialSupplier) {
            // create members
            let conversation_id = conversation_id();
            let (alice_backend, mut alice) = alice(credential).await.unwrap();
            let (bob_backend, bob) = bob(credential).await.unwrap();
            let (charlie_backend, charlie) = charlie(credential).await.unwrap();

            let bob_key = bob.local_client().keypackages(&bob_backend).await.unwrap()[0].clone();
            let charlie_key = charlie.local_client().keypackages(&charlie_backend).await.unwrap()[0].clone();

            let configuration = MlsConversationConfiguration::default();

            // create group
            let mut alice_group = MlsConversation::create(
                conversation_id,
                alice.local_client_mut(),
                configuration.clone(),
                &alice_backend,
            )
            .await
            .unwrap();

            // adding bob and creating the group on bob's side
            let add_message = alice_group
                .as_can_handshake()
                .add_members(&mut [bob], &alice_backend)
                .await
                .unwrap();
            alice_group
                .as_can_merge()
                .commit_accepted(&alice_backend)
                .await
                .unwrap();

            assert_eq!(alice_group.members().len(), 2);

            let MlsConversationCreationMessage { welcome, .. } = add_message;

            let mut bob_group = MlsConversation::from_welcome_message(welcome, configuration.clone(), &bob_backend)
                .await
                .unwrap();

            let bob_keys = bob_group.group.members();
            let alice_keys = alice_group.group.members();

            // checking that the members on both sides are the same
            assert!(alice_keys.iter().all(|a_key| bob_keys.contains(a_key)));

            let alice_key = alice_keys.into_iter().find(|&k| *k != bob_key).unwrap().clone();

            // proposing adding charlie
            let proposal_response = alice_group
                .group
                .propose_add_member(&alice_backend, &charlie_key)
                .await
                .unwrap();

            // receiving the proposal on bob's side
            assert!(bob_group
                .as_can_decrypt()
                .decrypt_message(&proposal_response.to_bytes().unwrap(), &bob_backend)
                .await
                .unwrap()
                .0
                .is_none());
            assert_eq!(alice_group.group.members().len(), 2);

            // performing an update on the alice's key. this should generate a welcome for charlie
            let (message, welcome) = alice_group
                .as_can_handshake()
                .update_keying_material(&alice_backend)
                .await
                .unwrap();
            assert!(welcome.is_some());
            assert!(alice_group.group.members().contains(&&alice_key));
            alice_group
                .as_can_merge()
                .commit_accepted(&alice_backend)
                .await
                .unwrap();
            // before merging, commit is not applied
            assert!(!alice_group.group.members().contains(&&alice_key));

            // create the group on charlie's side
            let charlie_welcome = welcome.unwrap();
            let mut charlie_group =
                MlsConversation::from_welcome_message(charlie_welcome, configuration, &charlie_backend)
                    .await
                    .unwrap();

            assert_eq!(alice_group.members().len(), 3);
            assert_eq!(charlie_group.members().len(), 3);
            // bob still didn't receive the message with the updated key and charlie's addition
            assert_eq!(bob_group.members().len(), 2);

            let alice_new_keys = alice_group.group.members();

            assert!(!alice_new_keys.contains(&&alice_key));

            // receiving the key update and the charlie's addition to the group
            assert!(bob_group
                .as_can_decrypt()
                .decrypt_message(&message.to_bytes().unwrap(), &bob_backend)
                .await
                .unwrap()
                .0
                .is_none());
            assert_eq!(bob_group.members().len(), 3);

            let bob_new_keys = bob_group.group.members();

            assert!(alice_new_keys.iter().all(|a_key| bob_new_keys.contains(a_key)));

            // ensure all parties can encrypt messages
            let msg = b"Hello World";
            let bob_can_send_message = bob_group.as_can_encrypt().encrypt_message(msg, &bob_backend).await;
            assert!(bob_can_send_message.is_ok());

            let alice_can_send_message = alice_group.as_can_encrypt().encrypt_message(msg, &alice_backend).await;
            assert!(alice_can_send_message.is_ok());

            let charlie_can_send_message = charlie_group
                .as_can_encrypt()
                .encrypt_message(msg, &charlie_backend)
                .await;
            assert!(charlie_can_send_message.is_ok());
        }
    }
}
