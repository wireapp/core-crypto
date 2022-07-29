//! Handshake refers here to either a commit or proposal message. Overall, it covers all the
//! operation modifying the group state
//!
//! This table summarizes when a MLS group can create a commit or proposal:
//!
//! | can create handshake ? | 0 pend. Commit | 1 pend. Commit |
//! |------------------------|----------------|----------------|
//! | 0 pend. Proposal       | ✅              | ❌              |
//! | 1+ pend. Proposal      | ✅              | ❌              |

use openmls::prelude::{KeyPackage, KeyPackageRef, MlsMessageOut, Welcome};
use openmls_traits::OpenMlsCryptoProvider;

use mls_crypto_provider::MlsCryptoProvider;

use crate::{member::ConversationMember, ClientId, ConversationId, CryptoError, CryptoResult, MlsCentral, MlsError};

use super::MlsConversation;

/// Returned when initializing a conversation through a commit.
/// Different from conversation created from a [`Welcome`] message or an external commit.
#[derive(Debug)]
pub struct MlsConversationCreationMessage {
    /// A welcome message for new members to join the group
    pub welcome: Welcome,
    /// Commit message adding members to the group
    pub commit: MlsMessageOut,
}

impl MlsConversationCreationMessage {
    /// Serializes both wrapped objects into TLS and return them as a tuple of byte arrays.
    /// 0 -> welcome
    /// 1 -> message
    pub fn to_bytes_pairs(&self) -> CryptoResult<(Vec<u8>, Vec<u8>)> {
        use openmls::prelude::TlsSerializeTrait as _;
        let welcome = self.welcome.tls_serialize_detached().map_err(MlsError::from)?;

        let msg = self.commit.to_bytes().map_err(MlsError::from)?;

        Ok((welcome, msg))
    }
}

/// Returned when a commit is created
#[derive(Debug)]
pub struct MlsCommitBundle {
    /// A welcome message if there are pending Add proposals
    pub welcome: Option<Welcome>,
    /// The commit message
    pub commit: MlsMessageOut,
}

impl MlsCommitBundle {
    /// Serializes both wrapped objects into TLS and return them as a tuple of byte arrays.
    /// 0 -> welcome
    /// 1 -> message
    pub fn to_bytes_pairs(&self) -> CryptoResult<(Option<Vec<u8>>, Vec<u8>)> {
        use openmls::prelude::TlsSerializeTrait as _;
        let welcome = self
            .welcome
            .as_ref()
            .map(|w| w.tls_serialize_detached().map_err(MlsError::from))
            .transpose()?;
        let msg = self.commit.to_bytes().map_err(MlsError::from)?;

        Ok((welcome, msg))
    }
}

/// Creating proposals
impl MlsConversation {
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
impl MlsConversation {
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

        let (commit, welcome) = self
            .group
            .add_members(backend, &keypackages)
            .await
            .map_err(MlsError::from)?;

        Ok(MlsConversationCreationMessage { welcome, commit })
    }

    /// see [MlsCentral::remove_members_from_conversation]
    /// Note: this is not exposed publicly because authorization isn't handled at this level
    pub(crate) async fn remove_members(
        &mut self,
        clients: &[ClientId],
        backend: &MlsCryptoProvider,
    ) -> CryptoResult<MlsCommitBundle> {
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

        let (commit, welcome) = self
            .group
            .remove_members(backend, &member_kps)
            .await
            .map_err(MlsError::from)?;

        Ok(MlsCommitBundle { commit, welcome })
    }

    /// see [MlsCentral::update_keying_material]
    pub async fn update_keying_material(&mut self, backend: &MlsCryptoProvider) -> CryptoResult<MlsCommitBundle> {
        Ok(self
            .group
            .self_update(backend, None)
            .await
            .map_err(MlsError::from)
            .map(|(commit, welcome)| MlsCommitBundle { welcome, commit })?)
    }

    /// see [MlsCentral::commit_pending_proposals]
    pub async fn commit_pending_proposals(&mut self, backend: &MlsCryptoProvider) -> CryptoResult<MlsCommitBundle> {
        Ok(self
            .group
            .commit_to_pending_proposals(backend)
            .await
            .map_err(MlsError::from)
            .map(|(commit, welcome)| MlsCommitBundle { welcome, commit })?)
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
    ) -> CryptoResult<MlsConversationCreationMessage> {
        if let Some(callbacks) = self.callbacks.as_ref() {
            if !callbacks.authorize(id.clone(), self.mls_client.id().to_string()) {
                return Err(CryptoError::Unauthorized);
            }
        }
        let add = Self::get_conversation_mut(&mut self.mls_groups, id)?
            .add_members(members, &self.mls_backend)
            .await?;
        self.maybe_accept_commit(id).await?;
        Ok(add)
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
    ) -> CryptoResult<MlsCommitBundle> {
        if let Some(callbacks) = self.callbacks.as_ref() {
            if !callbacks.authorize(id.clone(), self.mls_client.id().to_string()) {
                return Err(CryptoError::Unauthorized);
            }
        }
        let remove = Self::get_conversation_mut(&mut self.mls_groups, id)?
            .remove_members(clients, &self.mls_backend)
            .await?;
        self.maybe_accept_commit(id).await?;
        Ok(remove)
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
    pub async fn update_keying_material(&mut self, id: &ConversationId) -> CryptoResult<MlsCommitBundle> {
        let update = Self::get_conversation_mut(&mut self.mls_groups, id)?
            .update_keying_material(&self.mls_backend)
            .await;
        self.maybe_accept_commit(id).await?;
        update
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
    pub async fn commit_pending_proposals(&mut self, id: &ConversationId) -> CryptoResult<MlsCommitBundle> {
        let commit = Self::get_conversation_mut(&mut self.mls_groups, id)?
            .commit_pending_proposals(&self.mls_backend)
            .await;
        self.maybe_accept_commit(id).await?;
        commit
    }

    // Preserves "current" behaviour with auto-merged commits
    // TODO: remove when backend counterpart implemented
    #[cfg(feature = "strict-consistency")]
    async fn maybe_accept_commit(&mut self, _id: &ConversationId) -> CryptoResult<()> {
        Ok(())
    }

    // Preserves "current" behaviour with auto-merged commits
    // TODO: remove when backend counterpart implemented
    #[cfg(not(feature = "strict-consistency"))]
    async fn maybe_accept_commit(&mut self, id: &ConversationId) -> CryptoResult<()> {
        Self::get_conversation_mut(&mut self.mls_groups, id)?
            .commit_accepted(&self.mls_backend)
            .await
    }
}

#[cfg(test)]
pub mod tests {
    use crate::{credential::CredentialSupplier, proposal::MlsProposal, test_utils::*, MlsConversationConfiguration};
    use wasm_bindgen_test::*;

    use super::*;

    wasm_bindgen_test_configure!(run_in_browser);

    pub mod add_members {
        use super::*;

        #[apply(all_credential_types)]
        #[wasm_bindgen_test]
        pub async fn can_add_members_to_conversation(credential: CredentialSupplier) {
            run_test_with_client_ids(
                credential,
                ["alice", "bob"],
                move |[mut alice_central, mut bob_central]| {
                    Box::pin(async move {
                        let id = conversation_id();

                        alice_central
                            .new_conversation(id.clone(), MlsConversationConfiguration::default())
                            .await
                            .unwrap();
                        let MlsConversationCreationMessage { welcome, .. } = alice_central
                            .add_members_to_conversation(&id, &mut [bob_central.rnd_member().await])
                            .await
                            .unwrap();

                        // before merging, commit is not applied
                        assert_eq!(alice_central[&id].members().len(), 1);
                        alice_central.commit_accepted(&id).await.unwrap();

                        assert_eq!(alice_central[&id].id, id);
                        assert_eq!(alice_central[&id].group.group_id().as_slice(), id);
                        assert_eq!(alice_central[&id].members().len(), 2);

                        bob_central
                            .process_welcome_message(welcome, MlsConversationConfiguration::default())
                            .await
                            .unwrap();
                        assert_eq!(alice_central[&id].id(), bob_central[&id].id());
                        assert_eq!(bob_central[&id].members().len(), 2);
                        assert!(alice_central.talk_to(&id, &mut bob_central).await.is_ok());
                    })
                },
            )
            .await
        }
    }

    pub mod remove_members {
        use super::*;
        use crate::{test_fixture_utils::SuccessValidationCallbacks, CoreCryptoCallbacks};

        #[apply(all_credential_types)]
        #[wasm_bindgen_test]
        pub async fn alice_can_remove_bob_from_conversation(credential: CredentialSupplier) {
            run_test_with_client_ids(
                credential,
                ["alice", "bob"],
                move |[mut alice_central, mut bob_central]| {
                    Box::pin(async move {
                        let id = conversation_id();

                        alice_central
                            .new_conversation(id.clone(), MlsConversationConfiguration::default())
                            .await
                            .unwrap();
                        alice_central.invite(&id, &mut bob_central).await.unwrap();

                        let MlsCommitBundle { commit, .. } = alice_central
                            .remove_members_from_conversation(&id, &["bob".into()])
                            .await
                            .unwrap();

                        // before merging, commit is not applied
                        assert_eq!(alice_central[&id].members().len(), 2);
                        alice_central.commit_accepted(&id).await.unwrap();
                        assert_eq!(alice_central[&id].members().len(), 1);

                        bob_central
                            .decrypt_message(&id, commit.to_bytes().unwrap())
                            .await
                            .unwrap();

                        // But has been removed from the conversation
                        assert!(matches!(
                           bob_central.get_conversation(&id).unwrap_err(),
                            CryptoError::ConversationNotFound(conv_id) if conv_id == id
                        ));
                        assert!(alice_central.talk_to(&id, &mut bob_central).await.is_err());
                    })
                },
            )
            .await
            .unwrap();

            let messages = alice_group
                .add_members(&mut [bob.clone()], &alice_backend)
                .await
                .unwrap();
            alice_group.commit_accepted(&alice_backend).await.unwrap();

            assert_eq!(alice_group.members().len(), 2);

            let mut bob_group = MlsConversation::from_welcome_message(
                messages.welcome,
                MlsConversationConfiguration::default(),
                &bob_backend,
            )
            .await
            .unwrap();

            let remove_result = alice_group
                .remove_members(bob.clients().cloned().collect::<Vec<_>>().as_slice(), &alice_backend)
                .await
                .unwrap();
            // before merging, commit is not applied
            assert_eq!(alice_group.members().len(), 2);
            alice_group.commit_accepted(&alice_backend).await.unwrap();

            bob_group
                .decrypt_message(remove_result.to_bytes().unwrap(), &bob_backend)
                .await
                .unwrap();

            assert_eq!(alice_group.members().len(), 1);

            let alice_can_send_message = alice_group.encrypt_message(b"me", &alice_backend).await;
            assert!(alice_can_send_message.is_ok());
            let bob_cannot_send_message = alice_group.encrypt_message(b"me", &bob_backend).await;
            assert!(bob_cannot_send_message.is_err());
=======
            .await
            .unwrap();

            let messages = alice_group
                .add_members(&mut [bob.clone()], &alice_backend)
                .await
                .unwrap();
            alice_group.commit_accepted(&alice_backend).await.unwrap();

            assert_eq!(alice_group.members().len(), 2);

            let mut bob_group = MlsConversation::from_welcome_message(
                messages.welcome,
                MlsConversationConfiguration::default(),
                &bob_backend,
            )
            .await
            .unwrap();

            let remove_result = alice_group
                .remove_members(bob.clients().cloned().collect::<Vec<_>>().as_slice(), &alice_backend)
                .await
                .unwrap();
            // before merging, commit is not applied
            assert_eq!(alice_group.members().len(), 2);
            alice_group.commit_accepted(&alice_backend).await.unwrap();

            let callbacks: Option<Box<dyn CoreCryptoCallbacks>> = Some(Box::new(SuccessValidationCallbacks));
            bob_group
                .decrypt_message(
                    remove_result.to_bytes().unwrap(),
                    &bob_backend,
                    callbacks.as_ref().map(|boxed| boxed.as_ref()),
                )
                .await
                .unwrap();

            assert_eq!(alice_group.members().len(), 1);

            let alice_can_send_message = alice_group.encrypt_message(b"me", &alice_backend).await;
            assert!(alice_can_send_message.is_ok());
            let bob_cannot_send_message = alice_group.encrypt_message(b"me", &bob_backend).await;
            assert!(bob_cannot_send_message.is_err());
>>>>>>> 783f931 (Adding validation to external proposal)
        }
    }

    pub mod update_keying_material {
        use crate::CoreCryptoCallbacks;

        use super::*;

        #[apply(all_credential_types)]
        #[wasm_bindgen_test]
        pub async fn should_update_keying_material_conversation_group(credential: CredentialSupplier) {
            run_test_with_client_ids(
                credential,
                ["alice", "bob"],
                move |[mut alice_central, mut bob_central]| {
                    Box::pin(async move {
                        let id = conversation_id();
                        alice_central
                            .new_conversation(id.clone(), MlsConversationConfiguration::default())
                            .await
                            .unwrap();
                        alice_central.invite(&id, &mut bob_central).await.unwrap();

                        let bob_keys = bob_central[&id].group.members();
                        let alice_keys = alice_central[&id].group.members();
                        assert!(alice_keys.iter().all(|a_key| bob_keys.contains(a_key)));

                        let alice_key = alice_central.key_package_of(&id, "alice");

                        // proposing the key update for alice
                        let MlsCommitBundle { commit, welcome } =
                            alice_central.update_keying_material(&id).await.unwrap();
                        assert!(welcome.is_none());

                        // before merging, commit is not applied
                        assert!(alice_central[&id].group.members().contains(&&alice_key));
                        alice_central.commit_accepted(&id).await.unwrap();
                        let alice_new_keys = alice_central[&id].group.members();
                        assert!(!alice_new_keys.contains(&&alice_key));

                        // receiving the commit on bob's side (updating key from alice)
                        bob_central
                            .decrypt_message(&id, &commit.to_bytes().unwrap())
                            .await
                            .unwrap();

                        let bob_new_keys = bob_central[&id].group.members();
                        assert!(alice_new_keys.iter().all(|a_key| bob_new_keys.contains(a_key)));

                        // ensuring both can encrypt messages
                        assert!(alice_central.talk_to(&id, &mut bob_central).await.is_ok());
                    })
                },
            )
            .await
            .unwrap();

            let add_message = alice_group.add_members(&mut [bob], &alice_backend).await.unwrap();
            alice_group.commit_accepted(&alice_backend).await.unwrap();

            assert_eq!(alice_group.members().len(), 2);

            let MlsConversationCreationMessage { welcome, .. } = add_message;

            // creating group on bob's side
            let mut bob_group = MlsConversation::from_welcome_message(welcome, configuration, &bob_backend)
                .await
                .unwrap();

            // ensuring both sides can encrypt messages
            let msg = b"Hello";
            let alice_can_send_message = alice_group.encrypt_message(msg, &alice_backend).await;
            assert!(alice_can_send_message.is_ok());
            let bob_can_send_message = bob_group.encrypt_message(msg, &bob_backend).await;
            assert!(bob_can_send_message.is_ok());

            let bob_keys = bob_group.group.members();
            let alice_keys = alice_group.group.members();
            assert!(alice_keys.iter().all(|a_key| bob_keys.contains(a_key)));

            let alice_key = alice_keys.into_iter().find(|&k| *k != bob_key).unwrap().clone();
            // proposing the key update for alice
            let (msg_out, welcome) = alice_group.update_keying_material(&alice_backend).await.unwrap();
            assert!(welcome.is_none());

            // before merging, commit is not applied
            assert!(alice_group.group.members().contains(&&alice_key));
            alice_group.commit_accepted(&alice_backend).await.unwrap();

            let alice_new_keys = alice_group.group.members();
            assert!(!alice_new_keys.contains(&&alice_key));

            // receiving the commit on bob's side (updating key from alice)
            assert!(bob_group
                .decrypt_message(&msg_out.to_bytes().unwrap(), &bob_backend)
                .await
                .unwrap()
                .app_msg
                .is_none());

            let bob_new_keys = bob_group
                .group
                .members()
                .into_iter()
                .cloned()
                .collect::<Vec<KeyPackage>>();

            assert!(alice_new_keys.iter().all(|a_key| bob_new_keys.contains(a_key)));

            // ensuring both can encrypt messages
            let bob_can_send_message = bob_group.encrypt_message(msg, &bob_backend).await;
            assert!(bob_can_send_message.is_ok());

            let alice_can_send_message = alice_group.encrypt_message(msg, &alice_backend).await;
            assert!(alice_can_send_message.is_ok());
=======
            .await
            .unwrap();

            let add_message = alice_group.add_members(&mut [bob], &alice_backend).await.unwrap();
            alice_group.commit_accepted(&alice_backend).await.unwrap();

            assert_eq!(alice_group.members().len(), 2);

            let MlsConversationCreationMessage { welcome, .. } = add_message;

            // creating group on bob's side
            let mut bob_group = MlsConversation::from_welcome_message(welcome, configuration, &bob_backend)
                .await
                .unwrap();

            // ensuring both sides can encrypt messages
            let msg = b"Hello";
            let alice_can_send_message = alice_group.encrypt_message(msg, &alice_backend).await;
            assert!(alice_can_send_message.is_ok());
            let bob_can_send_message = bob_group.encrypt_message(msg, &bob_backend).await;
            assert!(bob_can_send_message.is_ok());

            let bob_keys = bob_group.group.members();
            let alice_keys = alice_group.group.members();
            assert!(alice_keys.iter().all(|a_key| bob_keys.contains(a_key)));

            let alice_key = alice_keys.into_iter().find(|&k| *k != bob_key).unwrap().clone();
            // proposing the key update for alice
            let (msg_out, welcome) = alice_group.update_keying_material(&alice_backend).await.unwrap();
            assert!(welcome.is_none());

            // before merging, commit is not applied
            assert!(alice_group.group.members().contains(&&alice_key));
            alice_group.commit_accepted(&alice_backend).await.unwrap();

            let alice_new_keys = alice_group.group.members();
            assert!(!alice_new_keys.contains(&&alice_key));

            // receiving the commit on bob's side (updating key from alice)
            let callbacks: Option<Box<dyn CoreCryptoCallbacks>> = Some(Box::new(SuccessValidationCallbacks));
            assert!(bob_group
                .decrypt_message(
                    &msg_out.to_bytes().unwrap(),
                    &bob_backend,
                    callbacks.as_ref().map(|boxed| boxed.as_ref()),
                )
                .await
                .unwrap()
                .app_msg
                .is_none());

            let bob_new_keys = bob_group
                .group
                .members()
                .into_iter()
                .cloned()
                .collect::<Vec<KeyPackage>>();

            assert!(alice_new_keys.iter().all(|a_key| bob_new_keys.contains(a_key)));

            // ensuring both can encrypt messages
            let bob_can_send_message = bob_group.encrypt_message(msg, &bob_backend).await;
            assert!(bob_can_send_message.is_ok());

            let alice_can_send_message = alice_group.encrypt_message(msg, &alice_backend).await;
            assert!(alice_can_send_message.is_ok());
>>>>>>> 783f931 (Adding validation to external proposal)
        }

        #[apply(all_credential_types)]
        #[wasm_bindgen_test]
        pub async fn should_update_keying_material_group_pending_commit(credential: CredentialSupplier) {
            run_test_with_client_ids(
                credential,
                ["alice", "bob", "charlie"],
                move |[mut alice_central, mut bob_central, mut charlie_central]| {
                    Box::pin(async move {
                        let id = conversation_id();
                        alice_central
                            .new_conversation(id.clone(), MlsConversationConfiguration::default())
                            .await
                            .unwrap();
                        alice_central.invite(&id, &mut bob_central).await.unwrap();

                        let bob_keys = bob_central[&id].group.members();
                        let alice_keys = alice_central[&id].group.members();

                        // checking that the members on both sides are the same
                        assert!(alice_keys.iter().all(|a_key| bob_keys.contains(a_key)));

                        let alice_key = alice_central.key_package_of(&id, "alice");

                        // proposing adding charlie
                        let charlie_kp = charlie_central.get_one_key_package().await;
                        let add_charlie_proposal = alice_central
                            .new_proposal(&id, MlsProposal::Add(charlie_kp))
                            .await
                            .unwrap();

                        // receiving the proposal on Bob's side
                        bob_central
                            .decrypt_message(&id, add_charlie_proposal.to_bytes().unwrap())
                            .await
                            .unwrap();

                        // performing an update on Alice's key. this should generate a welcome for Charlie
                        let MlsCommitBundle { commit, welcome } =
                            alice_central.update_keying_material(&id).await.unwrap();
                        assert!(welcome.is_some());
                        assert!(alice_central[&id].group.members().contains(&&alice_key));
                        alice_central.commit_accepted(&id).await.unwrap();
                        assert!(!alice_central[&id].group.members().contains(&&alice_key));

                        // create the group on charlie's side
                        charlie_central
                            .process_welcome_message(welcome.unwrap(), MlsConversationConfiguration::default())
                            .await
                            .unwrap();

                        assert_eq!(alice_central[&id].members().len(), 3);
                        assert_eq!(charlie_central[&id].members().len(), 3);
                        // bob still didn't receive the message with the updated key and charlie's addition
                        assert_eq!(bob_central[&id].members().len(), 2);

                        let alice_new_keys = alice_central[&id].group.members();
                        assert!(!alice_new_keys.contains(&&alice_key));

                        // receiving the key update and the charlie's addition to the group
                        bob_central
                            .decrypt_message(&id, &commit.to_bytes().unwrap())
                            .await
                            .unwrap();
                        assert_eq!(bob_central[&id].members().len(), 3);

                        let bob_new_keys = bob_central[&id].group.members();
                        assert!(alice_new_keys.iter().all(|a_key| bob_new_keys.contains(a_key)));

                        // ensure all parties can encrypt messages
                        assert!(alice_central.talk_to(&id, &mut bob_central).await.is_ok());
                        assert!(bob_central.talk_to(&id, &mut charlie_central).await.is_ok());
                        assert!(charlie_central.talk_to(&id, &mut alice_central).await.is_ok());
                    })
                },
            )
            .await
            .unwrap();

            // adding bob and creating the group on bob's side
            let MlsConversationCreationMessage { welcome, .. } =
                alice_group.add_members(&mut [bob], &alice_backend).await.unwrap();
            alice_group.commit_accepted(&alice_backend).await.unwrap();

            assert_eq!(alice_group.members().len(), 2);

            let mut bob_group = MlsConversation::from_welcome_message(welcome, configuration.clone(), &bob_backend)
                .await
                .unwrap();

            let bob_keys = bob_group.group.members();
            let alice_keys = alice_group.group.members();

            // checking that the members on both sides are the same
            assert!(alice_keys.iter().all(|a_key| bob_keys.contains(a_key)));

            let alice_key = alice_keys.into_iter().find(|&k| *k != bob_key).unwrap().clone();

            // proposing adding charlie
            let add_charlie_proposal = alice_group
                .group
                .propose_add_member(&alice_backend, &charlie_key)
                .await
                .unwrap();

            // receiving the proposal on bob's side
            assert!(bob_group
                .decrypt_message(&add_charlie_proposal.to_bytes().unwrap(), &bob_backend)
                .await
                .unwrap()
                .app_msg
                .is_none());
            assert_eq!(alice_group.group.members().len(), 2);

            // performing an update on the alice's key. this should generate a welcome for charlie
            let (commit, welcome) = alice_group.update_keying_material(&alice_backend).await.unwrap();
            assert!(welcome.is_some());
            assert!(alice_group.group.members().contains(&&alice_key));
            alice_group.commit_accepted(&alice_backend).await.unwrap();
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
                .decrypt_message(&commit.to_bytes().unwrap(), &bob_backend)
                .await
                .unwrap()
                .app_msg
                .is_none());
            assert_eq!(bob_group.members().len(), 3);

            let bob_new_keys = bob_group.group.members();

            assert!(alice_new_keys.iter().all(|a_key| bob_new_keys.contains(a_key)));

            // ensure all parties can encrypt messages
            let msg = b"Hello World";
            let bob_can_send_message = bob_group.encrypt_message(msg, &bob_backend).await;
            assert!(bob_can_send_message.is_ok());

            let alice_can_send_message = alice_group.encrypt_message(msg, &alice_backend).await;
            assert!(alice_can_send_message.is_ok());

            let charlie_can_send_message = charlie_group.encrypt_message(msg, &charlie_backend).await;
            assert!(charlie_can_send_message.is_ok());
=======
            .await
            .unwrap();

            // adding bob and creating the group on bob's side
            let MlsConversationCreationMessage { welcome, .. } =
                alice_group.add_members(&mut [bob], &alice_backend).await.unwrap();
            alice_group.commit_accepted(&alice_backend).await.unwrap();

            assert_eq!(alice_group.members().len(), 2);

            let mut bob_group = MlsConversation::from_welcome_message(welcome, configuration.clone(), &bob_backend)
                .await
                .unwrap();

            let bob_keys = bob_group.group.members();
            let alice_keys = alice_group.group.members();

            // checking that the members on both sides are the same
            assert!(alice_keys.iter().all(|a_key| bob_keys.contains(a_key)));

            let alice_key = alice_keys.into_iter().find(|&k| *k != bob_key).unwrap().clone();

            // proposing adding charlie
            let add_charlie_proposal = alice_group
                .group
                .propose_add_member(&alice_backend, &charlie_key)
                .await
                .unwrap();

            // receiving the proposal on bob's side
            let callbacks: Option<Box<dyn CoreCryptoCallbacks>> = Some(Box::new(SuccessValidationCallbacks));
            assert!(bob_group
                .decrypt_message(
                    &add_charlie_proposal.to_bytes().unwrap(),
                    &bob_backend,
                    callbacks.as_ref().map(|boxed| boxed.as_ref()),
                )
                .await
                .unwrap()
                .app_msg
                .is_none());
            assert_eq!(alice_group.group.members().len(), 2);

            // performing an update on the alice's key. this should generate a welcome for charlie
            let (commit, welcome) = alice_group.update_keying_material(&alice_backend).await.unwrap();
            assert!(welcome.is_some());
            assert!(alice_group.group.members().contains(&&alice_key));
            alice_group.commit_accepted(&alice_backend).await.unwrap();
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
                .decrypt_message(
                    &commit.to_bytes().unwrap(),
                    &bob_backend,
                    callbacks.as_ref().map(|boxed| boxed.as_ref()),
                )
                .await
                .unwrap()
                .app_msg
                .is_none());
            assert_eq!(bob_group.members().len(), 3);

            let bob_new_keys = bob_group.group.members();

            assert!(alice_new_keys.iter().all(|a_key| bob_new_keys.contains(a_key)));

            // ensure all parties can encrypt messages
            let msg = b"Hello World";
            let bob_can_send_message = bob_group.encrypt_message(msg, &bob_backend).await;
            assert!(bob_can_send_message.is_ok());

            let alice_can_send_message = alice_group.encrypt_message(msg, &alice_backend).await;
            assert!(alice_can_send_message.is_ok());

            let charlie_can_send_message = charlie_group.encrypt_message(msg, &charlie_backend).await;
            assert!(charlie_can_send_message.is_ok());
>>>>>>> 783f931 (Adding validation to external proposal)
        }
    }
}
