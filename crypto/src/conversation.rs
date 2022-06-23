// Wire
// Copyright (C) 2022 Wire Swiss GmbH

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with this program. If not, see http://www.gnu.org/licenses/.

use crate::ClientId;
use mls_crypto_provider::MlsCryptoProvider;
use openmls::{
    framing::{MlsMessageOut, ProcessedMessage},
    group::MlsGroup,
    messages::Welcome,
    prelude::{KeyPackage, KeyPackageRef, SenderRatchetConfiguration},
};
use openmls_traits::OpenMlsCryptoProvider;

use crate::{
    client::Client,
    member::{ConversationMember, MemberId},
    CryptoError, CryptoResult, MlsCiphersuite, MlsError,
};

pub type ConversationId = Vec<u8>;

#[derive(Debug, Default, Clone)]
pub struct MlsConversationConfiguration {
    pub admins: Vec<MemberId>,
    pub ciphersuite: MlsCiphersuite,
    // TODO: Implement the key rotation manually instead.
    pub key_rotation_span: Option<std::time::Duration>,
}

impl MlsConversationConfiguration {
    #[inline(always)]
    pub fn openmls_default_configuration() -> openmls::group::MlsGroupConfig {
        openmls::group::MlsGroupConfig::builder()
            .wire_format_policy(openmls::group::MIXED_PLAINTEXT_WIRE_FORMAT_POLICY)
            .max_past_epochs(3)
            .padding_size(16)
            .number_of_resumtion_secrets(1)
            // TODO: Choose appropriate values
            .sender_ratchet_configuration(SenderRatchetConfiguration::new(2, 5))
            .use_ratchet_tree_extension(true)
            .build()
    }
}

#[derive(Debug)]
#[allow(dead_code)]
pub struct MlsConversation {
    pub(crate) id: ConversationId,
    pub(crate) group: MlsGroup,
    pub(crate) admins: Vec<MemberId>,
    configuration: MlsConversationConfiguration,
}

#[derive(Debug)]
pub struct MlsConversationCreationMessage {
    pub welcome: Welcome,
    pub message: MlsMessageOut,
}

#[derive(Debug)]
pub struct MlsConversationLeaveMessage {
    pub self_removal_proposal: MlsMessageOut,
    pub other_clients_removal_commit: Option<MlsMessageOut>,
}

impl MlsConversationCreationMessage {
    /// Order is (welcome, message)
    pub fn to_bytes_pairs(&self) -> CryptoResult<(Vec<u8>, Vec<u8>)> {
        use openmls::prelude::TlsSerializeTrait as _;
        let welcome = self.welcome.tls_serialize_detached().map_err(MlsError::from)?;

        let msg = self.message.to_bytes().map_err(MlsError::from)?;

        Ok((welcome, msg))
    }
}

impl MlsConversation {
    pub fn create(
        id: ConversationId,
        author_client: &mut Client,
        config: MlsConversationConfiguration,
        backend: &MlsCryptoProvider,
    ) -> CryptoResult<Self> {
        let mls_group_config = MlsConversationConfiguration::openmls_default_configuration();
        let kp_hash = author_client.keypackage_raw_hash(backend)?;

        let group = MlsGroup::new(
            backend,
            &mls_group_config,
            openmls::group::GroupId::from_slice(&id),
            &kp_hash,
        )
        .map_err(MlsError::from)?;

        let mut conversation = Self {
            id,
            group,
            admins: config.admins.clone(),
            configuration: config,
        };

        conversation.persist_group_when_changed(backend, true)?;

        Ok(conversation)
    }

    // ? Do we need to provide the ratchet_tree to the MlsGroup? Does everything crumble down if we can't actually get it?
    /// Create the MLS conversation from an MLS Welcome message
    pub fn from_welcome_message(
        welcome: Welcome,
        configuration: MlsConversationConfiguration,
        backend: &MlsCryptoProvider,
    ) -> CryptoResult<Self> {
        let mls_group_config = MlsConversationConfiguration::openmls_default_configuration();
        let mut group =
            MlsGroup::new_from_welcome(backend, &mls_group_config, welcome, None).map_err(MlsError::from)?;

        let id = ConversationId::from(group.group_id().as_slice());

        let mut buf = vec![];
        group.save(&mut buf)?;
        use core_crypto_keystore::CryptoKeystoreMls as _;
        backend.key_store().mls_group_persist(&id, &buf)?;

        Ok(Self {
            id,
            admins: configuration.admins.clone(),
            group,
            configuration,
        })
    }

    /// Internal API: restore the conversation from a persistence-saved serialized Group State.
    pub(crate) fn from_serialized_state(buf: Vec<u8>) -> CryptoResult<Self> {
        let group = MlsGroup::load(&mut &buf[..])?;
        let id = ConversationId::from(group.group_id().as_slice());
        let configuration = MlsConversationConfiguration {
            ciphersuite: group.ciphersuite().into(),
            ..Default::default()
        };

        Ok(Self {
            id,
            group,
            configuration,
            admins: Default::default(),
        })
    }

    pub fn id(&self) -> &ConversationId {
        &self.id
    }

    pub fn members(&self) -> CryptoResult<std::collections::HashMap<MemberId, Vec<openmls::credentials::Credential>>> {
        self.group
            .members()
            .iter()
            .try_fold(std::collections::HashMap::new(), |mut acc, kp| -> CryptoResult<_> {
                let credential = kp.credential();
                let client_id: ClientId = credential.identity().into();
                let member_id: MemberId = client_id.to_vec();
                acc.entry(member_id).or_insert_with(Vec::new).push(credential.clone());

                Ok(acc)
            })
    }

    pub fn can_user_act(&self, uuid: MemberId) -> bool {
        self.admins.contains(&uuid)
    }

    /// Add new members to the conversation
    /// Note: this is not exposed publicly because authorization isn't handled at this level
    pub(crate) fn add_members(
        &mut self,
        members: &mut [ConversationMember],
        backend: &MlsCryptoProvider,
    ) -> CryptoResult<MlsConversationCreationMessage> {
        let keypackages = members
            .iter_mut()
            .flat_map(|member| member.keypackages_for_all_clients())
            .filter_map(|(_, kps)| kps)
            .collect::<Vec<KeyPackage>>();

        let (message, welcome) = self.group.add_members(backend, &keypackages).map_err(MlsError::from)?;
        self.group.merge_pending_commit().map_err(MlsError::from)?;

        self.persist_group_when_changed(backend, false)?;

        Ok(MlsConversationCreationMessage { welcome, message })
    }

    /// Remove members from the conversation
    /// Note: this is not exposed publicly because authorization isn't handled at this level
    pub(crate) fn remove_members(
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
                let identity = kp.external_key_id().unwrap_or_default();
                clients.iter().any(move |client_id| client_id.as_slice() == identity)
            })
            .try_fold(Vec::new(), |mut acc, kp| -> CryptoResult<Vec<KeyPackageRef>> {
                acc.push(kp.hash_ref(crypto).map_err(MlsError::from)?);
                Ok(acc)
            })?;

        let (message, _) = self
            .group
            .remove_members(backend, &member_kps)
            .map_err(MlsError::from)?;
        self.group.merge_pending_commit().map_err(MlsError::from)?;

        self.persist_group_when_changed(backend, false)?;

        Ok(message)
    }

    pub fn decrypt_message(
        &mut self,
        message: impl AsRef<[u8]>,
        backend: &MlsCryptoProvider,
    ) -> CryptoResult<Option<Vec<u8>>> {
        let msg_in = openmls::framing::MlsMessageIn::try_from_bytes(message.as_ref()).map_err(MlsError::from)?;

        let parsed_message = self.group.parse_message(msg_in, backend).map_err(MlsError::from)?;

        let message = self
            .group
            .process_unverified_message(parsed_message, None, backend)
            .map_err(MlsError::from)?;

        match message {
            ProcessedMessage::ApplicationMessage(app_msg) => {
                return Ok(Some(app_msg.into_bytes()));
            }
            ProcessedMessage::ProposalMessage(proposal) => {
                self.group.store_pending_proposal(*proposal);
            }
            ProcessedMessage::StagedCommitMessage(staged_commit) => {
                self.group.merge_staged_commit(*staged_commit).map_err(MlsError::from)?;
            }
        }

        self.persist_group_when_changed(backend, false)?;

        Ok(None)
    }

    pub fn commit_pending_proposals(
        &mut self,
        backend: &MlsCryptoProvider,
    ) -> CryptoResult<(MlsMessageOut, Option<Welcome>)> {
        let (message, welcome) = self
            .group
            .commit_to_pending_proposals(backend)
            .map_err(MlsError::from)?;
        self.group.merge_pending_commit().map_err(MlsError::from)?;

        self.persist_group_when_changed(backend, false)?;

        Ok((message, welcome))
    }

    pub fn encrypt_message(&mut self, message: impl AsRef<[u8]>, backend: &MlsCryptoProvider) -> CryptoResult<Vec<u8>> {
        self.group
            .create_message(backend, message.as_ref())
            .map_err(MlsError::from)
            .and_then(|m| m.to_bytes().map_err(MlsError::from))
            .map_err(CryptoError::from)
    }

    pub fn update_keying_material(
        &mut self,
        backend: &MlsCryptoProvider,
    ) -> CryptoResult<(MlsMessageOut, Option<Welcome>)> {
        Ok(self.group.self_update(backend, None).map_err(MlsError::from)?)
    }

    fn persist_group_when_changed(&mut self, backend: &MlsCryptoProvider, force: bool) -> CryptoResult<()> {
        if force || self.group.state_changed() == openmls::group::InnerState::Changed {
            let mut buf = vec![];
            self.group.save(&mut buf)?;

            use core_crypto_keystore::CryptoKeystoreMls as _;
            Ok(backend.key_store().mls_group_persist(&self.id, &buf)?)
        } else {
            Ok(())
        }
    }

    pub(crate) fn leave(
        &mut self,
        other_clients: &[ClientId],
        backend: &MlsCryptoProvider,
    ) -> CryptoResult<MlsConversationLeaveMessage> {
        let crypto = backend.crypto();

        let other_clients_removal_commit = if !other_clients.is_empty() {
            let other_clients_slice: Vec<&[u8]> = other_clients.iter().map(|c| c.as_slice()).collect();
            let other_keypackages: Vec<_> = self
                .group
                .members()
                .into_iter()
                .filter(|m| other_clients_slice.contains(&m.credential().identity()))
                .filter_map(|m| m.hash_ref(crypto).ok())
                .collect();

            if !other_keypackages.is_empty() {
                let (other_clients_removal_commit, _) = self
                    .group
                    .remove_members(backend, other_keypackages.as_slice())
                    .map_err(MlsError::from)?;

                self.group.merge_pending_commit().map_err(MlsError::from)?;

                Some(other_clients_removal_commit)
            } else {
                None
            }
        } else {
            None
        };

        let self_removal_proposal = self.group.leave_group(backend).map_err(MlsError::from)?;

        Ok(MlsConversationLeaveMessage {
            other_clients_removal_commit,
            self_removal_proposal,
        })
    }
}

#[cfg(test)]
pub mod tests {
    use super::{ConversationId, MlsConversation, MlsConversationConfiguration};
    use crate::{member::ConversationMember, prelude::MlsConversationCreationMessage};
    use mls_crypto_provider::MlsCryptoProvider;

    use wasm_bindgen_test::wasm_bindgen_test;
    wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_browser);

    #[inline(always)]
    pub fn init_keystore(identifier: &str) -> MlsCryptoProvider {
        MlsCryptoProvider::try_new_in_memory(identifier).unwrap()
    }

    pub mod create {
        use crate::CryptoResult;

        use super::*;

        #[test]
        #[wasm_bindgen_test]
        pub fn create_self_conversation_should_succeed() {
            let conversation_id = conversation_id();
            let (alice_backend, mut alice) = alice();
            let mut alice_group = MlsConversation::create(
                conversation_id.clone(),
                alice.local_client_mut(),
                MlsConversationConfiguration::default(),
                &alice_backend,
            )
            .unwrap();

            assert_eq!(alice_group.id, conversation_id);
            assert_eq!(alice_group.group.group_id().as_slice(), conversation_id);
            assert_eq!(alice_group.members().unwrap().len(), 1);
            let alice_can_send_message = alice_group.encrypt_message(b"me", &alice_backend);
            assert!(alice_can_send_message.is_ok());
        }

        #[test]
        #[wasm_bindgen_test]
        pub fn create_1_1_conversation_should_succeed() {
            let conversation_id = conversation_id();
            let (alice_backend, mut alice) = alice();
            let (bob_backend, bob) = bob();

            let mut alice_group = MlsConversation::create(
                conversation_id.clone(),
                alice.local_client_mut(),
                MlsConversationConfiguration::default(),
                &alice_backend,
            )
            .unwrap();

            let conversation_creation_message = alice_group.add_members(&mut [bob], &alice_backend).unwrap();

            assert_eq!(alice_group.id, conversation_id);
            assert_eq!(alice_group.group.group_id().as_slice(), conversation_id);
            assert_eq!(alice_group.members().unwrap().len(), 2);

            let MlsConversationCreationMessage { welcome, .. } = conversation_creation_message;

            let mut bob_group =
                MlsConversation::from_welcome_message(welcome, MlsConversationConfiguration::default(), &bob_backend)
                    .unwrap();

            assert_eq!(bob_group.id(), alice_group.id());

            let alice_can_send_message = alice_group.encrypt_message(b"me", &alice_backend);
            assert!(alice_can_send_message.is_ok());
            let bob_can_send_message = bob_group.encrypt_message(b"me", &bob_backend);
            assert!(bob_can_send_message.is_ok());
        }

        #[test]
        #[wasm_bindgen_test]
        pub fn create_100_people_conversation() {
            let (alice_backend, mut alice) = alice();
            let bob_and_friends = (0..99).fold(Vec::with_capacity(100), |mut acc, _| {
                let uuid = uuid::Uuid::new_v4();
                let backend = init_keystore(&uuid.hyphenated().to_string());

                let member = ConversationMember::random_generate(&backend).unwrap();
                acc.push((backend, member));
                acc
            });

            let number_of_friends = bob_and_friends.len();

            let conversation_id = conversation_id();

            let conversation_config = MlsConversationConfiguration::default();
            let mut alice_group = MlsConversation::create(
                conversation_id.clone(),
                alice.local_client_mut(),
                conversation_config.clone(),
                &alice_backend,
            )
            .unwrap();

            let mut bob_and_friends_members: Vec<ConversationMember> =
                bob_and_friends.iter().map(|(_, m)| m.clone()).collect();

            let conversation_creation_message = alice_group
                .add_members(&mut bob_and_friends_members, &alice_backend)
                .unwrap();

            assert_eq!(alice_group.id, conversation_id);
            assert_eq!(alice_group.group.group_id().as_slice(), conversation_id);
            assert_eq!(alice_group.members().unwrap().len(), 1 + number_of_friends);

            let MlsConversationCreationMessage { welcome, .. } = conversation_creation_message;

            let bob_and_friends_groups = bob_and_friends
                .iter()
                .map(|(backend, _)| {
                    MlsConversation::from_welcome_message(welcome.clone(), conversation_config.clone(), backend)
                })
                .collect::<CryptoResult<Vec<MlsConversation>>>()
                .unwrap();

            assert_eq!(bob_and_friends_groups.len(), 99);
        }
    }

    pub mod add_members {
        use super::*;

        #[test]
        #[wasm_bindgen_test]
        pub fn can_add_members_to_conversation() {
            let conversation_id = conversation_id();
            let (alice_backend, mut alice) = alice();
            let (bob_backend, bob) = bob();
            let conversation_config = MlsConversationConfiguration::default();
            let mut alice_group = MlsConversation::create(
                conversation_id.clone(),
                alice.local_client_mut(),
                conversation_config,
                &alice_backend,
            )
            .unwrap();

            let conversation_creation_message = alice_group.add_members(&mut [bob], &alice_backend).unwrap();

            assert_eq!(alice_group.id, conversation_id);
            assert_eq!(alice_group.group.group_id().as_slice(), conversation_id);
            assert_eq!(alice_group.members().unwrap().len(), 2);

            let MlsConversationCreationMessage { welcome, .. } = conversation_creation_message;

            let conversation_config = MlsConversationConfiguration::default();

            let mut bob_group =
                MlsConversation::from_welcome_message(welcome, conversation_config, &bob_backend).unwrap();

            assert_eq!(bob_group.id(), alice_group.id());

            let msg = b"Hello";
            let alice_can_send_message = alice_group.encrypt_message(msg, &alice_backend);
            assert!(alice_can_send_message.is_ok());
            let bob_can_send_message = bob_group.encrypt_message(msg, &bob_backend);
            assert!(bob_can_send_message.is_ok());
        }
    }

    pub mod remove_members {
        use super::*;

        #[test]
        #[wasm_bindgen_test]
        pub fn alice_can_remove_bob_from_conversation() {
            let conversation_id = conversation_id();
            let (alice_backend, mut alice) = alice();
            let (bob_backend, bob) = bob();
            let conversation_config = MlsConversationConfiguration::default();

            let mut alice_group = MlsConversation::create(
                conversation_id,
                alice.local_client_mut(),
                conversation_config,
                &alice_backend,
            )
            .unwrap();

            let messages = alice_group.add_members(&mut [bob.clone()], &alice_backend).unwrap();

            assert_eq!(alice_group.members().unwrap().len(), 2);

            let mut bob_group = MlsConversation::from_welcome_message(
                messages.welcome,
                MlsConversationConfiguration::default(),
                &bob_backend,
            )
            .unwrap();

            let remove_result = alice_group
                .remove_members(bob.clients().cloned().collect::<Vec<_>>().as_slice(), &alice_backend)
                .unwrap();

            bob_group
                .decrypt_message(remove_result.to_bytes().unwrap(), &bob_backend)
                .unwrap();

            assert_eq!(alice_group.members().unwrap().len(), 1);

            let alice_can_send_message = alice_group.encrypt_message(b"me", &alice_backend);
            assert!(alice_can_send_message.is_ok());
            let bob_cannot_send_message = alice_group.encrypt_message(b"me", &bob_backend);
            assert!(bob_cannot_send_message.is_err());
        }
    }

    pub mod encrypting_messages {
        use super::*;

        #[test]
        #[wasm_bindgen_test]
        pub fn can_roundtrip_message_in_1_1_conversation() {
            let conversation_id = conversation_id();
            let (alice_backend, mut alice) = alice();
            let (bob_backend, bob) = bob();
            let configuration = MlsConversationConfiguration::default();

            let mut alice_group = MlsConversation::create(
                conversation_id.clone(),
                alice.local_client_mut(),
                configuration,
                &alice_backend,
            )
            .unwrap();
            let conversation_creation_message = alice_group.add_members(&mut [bob], &alice_backend).unwrap();
            assert_eq!(alice_group.id, conversation_id);
            assert_eq!(alice_group.group.group_id().as_slice(), conversation_id);
            assert_eq!(alice_group.members().unwrap().len(), 2);

            let MlsConversationCreationMessage { welcome, .. } = conversation_creation_message;

            let mut bob_group =
                MlsConversation::from_welcome_message(welcome, MlsConversationConfiguration::default(), &bob_backend)
                    .unwrap();

            let original_message = b"Hello World!";

            // alice -> bob
            let encrypted_message = alice_group.encrypt_message(original_message, &alice_backend).unwrap();
            assert_ne!(&encrypted_message, original_message);
            let roundtripped_message = bob_group
                .decrypt_message(&encrypted_message, &bob_backend)
                .unwrap()
                .unwrap();
            assert_eq!(original_message, roundtripped_message.as_slice());

            // bob -> alice
            let encrypted_message = bob_group.encrypt_message(roundtripped_message, &bob_backend).unwrap();
            assert_ne!(&encrypted_message, original_message);
            let roundtripped_message = alice_group
                .decrypt_message(&encrypted_message, &alice_backend)
                .unwrap()
                .unwrap();
            assert_eq!(original_message, roundtripped_message.as_slice());
        }
    }

    pub mod leave {
        use super::*;

        #[test]
        #[wasm_bindgen_test]
        pub fn can_leave_conversation() {
            let alice_backend = init_keystore("alice");
            let alice2_backend = init_keystore("alice2");
            let bob_backend = init_keystore("bob");
            let charlie_backend = init_keystore("charlie");

            let mut alice = ConversationMember::random_generate(&alice_backend).unwrap();
            let alice2 = ConversationMember::random_generate(&alice2_backend).unwrap();
            let bob = ConversationMember::random_generate(&bob_backend).unwrap();
            let charlie = ConversationMember::random_generate(&charlie_backend).unwrap();

            let uuid = uuid::Uuid::new_v4();
            let conversation_id = ConversationId::from(format!("{}@conversations.wire.com", uuid.hyphenated()));

            let conversation_config = MlsConversationConfiguration { ..Default::default() };

            let mut alice_group = MlsConversation::create(
                conversation_id.clone(),
                alice.local_client_mut(),
                conversation_config,
                &alice_backend,
            )
            .unwrap();

            let conversation_creation_message = alice_group
                .add_members(&mut [alice2, bob, charlie], &alice_backend)
                .unwrap();

            assert_eq!(alice_group.id, conversation_id);
            assert_eq!(alice_group.group.group_id().as_slice(), conversation_id);
            assert_eq!(alice_group.members().unwrap().len(), 4);

            let MlsConversationCreationMessage { welcome, .. } = conversation_creation_message;

            let conversation_config = MlsConversationConfiguration::default();
            let mut bob_group =
                MlsConversation::from_welcome_message(welcome.clone(), conversation_config.clone(), &bob_backend)
                    .unwrap();
            let mut charlie_group =
                MlsConversation::from_welcome_message(welcome.clone(), conversation_config.clone(), &charlie_backend)
                    .unwrap();
            let mut alice2_group =
                MlsConversation::from_welcome_message(welcome, conversation_config, &alice2_backend).unwrap();

            assert_eq!(bob_group.id(), alice_group.id());
            assert_eq!(alice2_group.id(), alice_group.id());
            assert_eq!(charlie_group.id(), alice_group.id());
            assert_eq!(alice2_group.members().unwrap().len(), 4);
            assert_eq!(bob_group.members().unwrap().len(), 4);
            assert_eq!(charlie_group.members().unwrap().len(), 4);

            let message = alice2_group
                .leave(&[alice.id().clone().into()], &alice2_backend)
                .unwrap();

            // Only the `other_clients` have been effectively removed as of now
            // Removing alice2 will only be effective once bob or charlie commit the removal proposal that alice2 leaves
            assert_eq!(alice2_group.members().unwrap().len(), 3);
            bob_group
                .decrypt_message(
                    message
                        .other_clients_removal_commit
                        .as_ref()
                        .unwrap()
                        .to_bytes()
                        .unwrap(),
                    &bob_backend,
                )
                .unwrap();

            charlie_group
                .decrypt_message(
                    message
                        .other_clients_removal_commit
                        .as_ref()
                        .unwrap()
                        .to_bytes()
                        .unwrap(),
                    &bob_backend,
                )
                .unwrap();

            assert_eq!(bob_group.members().unwrap().len(), 3);
            assert_eq!(charlie_group.members().unwrap().len(), 3);

            alice_group
                .decrypt_message(
                    message
                        .other_clients_removal_commit
                        .as_ref()
                        .unwrap()
                        .to_bytes()
                        .unwrap(),
                    &alice_backend,
                )
                .unwrap();

            // alice_group is now unuseable
            assert!(alice_group.encrypt_message(b"test", &alice_backend).is_err());
            assert!(!alice_group.group.is_active());

            bob_group
                .decrypt_message(message.self_removal_proposal.to_bytes().unwrap(), &bob_backend)
                .unwrap();

            let (removal_commit_from_bob, _) = bob_group.commit_pending_proposals(&bob_backend).unwrap();

            charlie_group
                .decrypt_message(message.self_removal_proposal.to_bytes().unwrap(), &bob_backend)
                .unwrap();

            charlie_group
                .decrypt_message(removal_commit_from_bob.to_bytes().unwrap(), &charlie_backend)
                .unwrap();
            alice2_group
                .decrypt_message(removal_commit_from_bob.to_bytes().unwrap(), &alice2_backend)
                .unwrap();

            // Check that alice2 understood that she's not welcome anymore (sorry alice2)
            assert!(!alice2_group.group.is_active());

            assert_eq!(charlie_group.members().unwrap().len(), 2);
            assert_eq!(bob_group.members().unwrap().len(), 2);
        }
    }

    pub mod update_keying_material {
        use openmls::prelude::KeyPackage;
        use wasm_bindgen_test::wasm_bindgen_test;

        use crate::{
            conversation::tests::{alice, bob, charlie},
            prelude::{MlsConversation, MlsConversationConfiguration, MlsConversationCreationMessage},
        };

        use super::conversation_id;

        #[test]
        #[wasm_bindgen_test]
        pub fn should_update_keying_material_group_pending_commit() {
            // create members
            let conversation_id = conversation_id();
            let (bob_backend, bob) = bob();
            let (alice_backend, mut alice) = alice();
            let (charlie_backend, charlie) = charlie();
            let bob_key = bob.local_client().keypackages(&bob_backend).unwrap()[0].clone();
            let charlie_key = charlie.local_client().keypackages(&charlie_backend).unwrap()[0].clone();

            let configuration = MlsConversationConfiguration::default();

            // create group
            let mut alice_group = MlsConversation::create(
                conversation_id,
                alice.local_client_mut(),
                configuration.clone(),
                &alice_backend,
            )
            .unwrap();

            // adding bob and creating the group on bob's side
            let add_message = alice_group.add_members(&mut [bob], &alice_backend).unwrap();

            assert_eq!(alice_group.members().unwrap().len(), 2);

            let MlsConversationCreationMessage { welcome, .. } = add_message;

            let mut bob_group =
                MlsConversation::from_welcome_message(welcome, configuration.clone(), &bob_backend).unwrap();

            let bob_keys = bob_group
                .group
                .members()
                .into_iter()
                .cloned()
                .collect::<Vec<KeyPackage>>();

            let alice_keys = alice_group
                .group
                .members()
                .into_iter()
                .cloned()
                .collect::<Vec<KeyPackage>>();

            // checking that the members on both sides are the same
            assert!(alice_keys.iter().all(|a_key| bob_keys.contains(a_key)));

            let alice_key = alice_keys.into_iter().find(|k| *k != bob_key).unwrap();

            // proposing adding charlie
            let proposal_response = alice_group
                .group
                .propose_add_member(&alice_backend, &charlie_key)
                .unwrap();

            // receiving the proposal on bob's side
            assert!(bob_group
                .decrypt_message(&proposal_response.to_bytes().unwrap(), &bob_backend)
                .unwrap()
                .is_none());

            assert_eq!(alice_group.group.members().len(), 2);

            // performing an update on the alice's key. this should generate a welcome for charlie
            let (message, welcome) = alice_group.update_keying_material(&alice_backend).unwrap();
            assert!(welcome.is_some());

            alice_group.group.merge_pending_commit().unwrap();

            // create the group on charlie's side
            let charlie_welcome = welcome.unwrap();
            let mut charlie_group =
                MlsConversation::from_welcome_message(charlie_welcome, configuration, &charlie_backend).unwrap();

            assert_eq!(alice_group.members().unwrap().len(), 3);
            assert_eq!(charlie_group.members().unwrap().len(), 3);
            // bob still didn't receive the message with the updated key and charlie's addition
            assert_eq!(bob_group.members().unwrap().len(), 2);

            let alice_new_keys = alice_group
                .group
                .members()
                .into_iter()
                .cloned()
                .collect::<Vec<KeyPackage>>();

            assert!(!alice_new_keys.contains(&alice_key));

            // receiving the key update and the charlie's addition to the group
            assert!(bob_group
                .decrypt_message(&message.to_bytes().unwrap(), &bob_backend)
                .unwrap()
                .is_none());
            assert_eq!(bob_group.members().unwrap().len(), 3);

            let bob_new_keys = bob_group
                .group
                .members()
                .into_iter()
                .cloned()
                .collect::<Vec<KeyPackage>>();

            assert!(alice_new_keys.iter().all(|a_key| bob_new_keys.contains(a_key)));

            // ensure all parties can encrypt messages
            let msg = b"Hello World";
            let bob_can_send_message = bob_group.encrypt_message(msg, &bob_backend);
            assert!(bob_can_send_message.is_ok());

            let alice_can_send_message = alice_group.encrypt_message(msg, &alice_backend);
            assert!(alice_can_send_message.is_ok());

            let charlie_can_send_message = charlie_group.encrypt_message(msg, &charlie_backend);
            assert!(charlie_can_send_message.is_ok());
        }
    }

    fn conversation_id() -> Vec<u8> {
        let uuid = uuid::Uuid::new_v4();
        ConversationId::from(format!("{}@conversations.wire.com", uuid.hyphenated()))
    }

    fn alice() -> (MlsCryptoProvider, ConversationMember) {
        let alice_backend = init_keystore("alice");
        let alice = ConversationMember::random_generate(&alice_backend).unwrap();
        (alice_backend, alice)
    }

    fn charlie() -> (MlsCryptoProvider, ConversationMember) {
        let alice_backend = init_keystore("charlie");
        let alice = ConversationMember::random_generate(&alice_backend).unwrap();
        (alice_backend, alice)
    }

    fn bob() -> (MlsCryptoProvider, ConversationMember) {
        let bob_backend = init_keystore("bob");
        let bob = ConversationMember::random_generate(&bob_backend).unwrap();
        (bob_backend, bob)
    }
}
