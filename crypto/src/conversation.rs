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
use openmls::prelude::KeyPackageRef;
use openmls::{
    framing::{MlsMessageOut, ProcessedMessage},
    group::MlsGroup,
    messages::Welcome,
    prelude::{KeyPackage, SenderRatchetConfiguration},
};
use openmls_traits::OpenMlsCryptoProvider;

use crate::{
    client::Client,
    member::{ConversationMember, MemberId},
    CryptoError, CryptoResult, MlsCiphersuite, MlsError,
};

pub type ConversationId = Vec<u8>;

#[derive(Debug, Default, Clone, derive_builder::Builder)]
pub struct MlsConversationConfiguration {
    #[builder(default)]
    pub extra_members: Vec<ConversationMember>,
    #[builder(default)]
    pub admins: Vec<MemberId>,
    #[builder(default)]
    pub ciphersuite: MlsCiphersuite,
    // TODO: Implement the key rotation manually instead.
    #[builder(default)]
    pub key_rotation_span: Option<std::time::Duration>,
}

impl MlsConversationConfiguration {
    pub fn builder() -> MlsConversationConfigurationBuilder {
        MlsConversationConfigurationBuilder::default()
    }

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
    pub(crate) group: std::sync::RwLock<MlsGroup>,
    pub(crate) admins: Vec<MemberId>,
    configuration: MlsConversationConfiguration,
}

#[derive(Debug)]
pub struct MlsConversationCreationMessage {
    pub welcome: Welcome,
    pub message: MlsMessageOut,
}

#[derive(Debug)]
pub struct MlsConversationReinitMessage {
    pub welcome: Option<Welcome>,
    pub message: MlsMessageOut,
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
    ) -> CryptoResult<(Self, Option<MlsConversationCreationMessage>)> {
        let mls_group_config = MlsConversationConfiguration::openmls_default_configuration();

        let mut group = MlsGroup::new(
            backend,
            &mls_group_config,
            openmls::group::GroupId::from_slice(&id),
            &author_client.keypackage_hash(backend)?,
        )
        .map_err(MlsError::from)?;

        let mut maybe_creation_message = None;
        if !config.extra_members.is_empty() {
            let kps: Vec<KeyPackage> = config
                .extra_members
                .clone()
                .into_iter()
                .flat_map(|mut m| {
                    m.keypackages_for_all_clients()
                        .into_iter()
                        .filter_map(|(_cid, maybe_kp)| maybe_kp)
                        .collect::<Vec<KeyPackage>>()
                })
                .collect();

            let (message, welcome) = group.add_members(backend, &kps).map_err(MlsError::from)?;

            group.merge_pending_commit().map_err(MlsError::from)?;

            maybe_creation_message = Some(MlsConversationCreationMessage { message, welcome });
        }

        let mut buf = vec![];
        group.save(&mut buf)?;
        backend.key_store().mls_group_persist(&id, &buf)?;

        let conversation = Self {
            id,
            group: group.into(),
            admins: config.admins.clone(),
            configuration: config,
        };

        Ok((conversation, maybe_creation_message))
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
        backend.key_store().mls_group_persist(&id, &buf)?;

        Ok(Self {
            id,
            admins: configuration.admins.clone(),
            group: group.into(),
            configuration,
        })
    }

    /// Internal API: restore the conversation from a persistence-saved serialized Group State.
    pub(crate) fn from_serialized_state(buf: Vec<u8>) -> CryptoResult<Self> {
        let group = MlsGroup::load(&mut &buf[..])?;
        let id = ConversationId::from(group.group_id().as_slice());
        let configuration = MlsConversationConfiguration::builder()
            .ciphersuite(group.ciphersuite().into())
            .build()?;

        Ok(Self {
            id,
            group: group.into(),
            configuration,
            admins: Default::default(),
        })
    }

    pub fn id(&self) -> &ConversationId {
        &self.id
    }

    pub fn members(&self) -> CryptoResult<std::collections::HashMap<MemberId, Vec<openmls::credentials::Credential>>> {
        Ok(self
            .group
            .read()
            .map_err(|_| CryptoError::LockPoisonError)?
            .members()
            .iter()
            .try_fold(std::collections::HashMap::new(), |mut acc, kp| -> CryptoResult<_> {
                let credential = kp.credential();
                let client_id: crate::client::ClientId = credential.identity().into();
                let member_id: MemberId = client_id.to_vec();
                acc.entry(member_id)
                    .or_insert_with(|| vec![])
                    .push((*credential).clone());

                Ok(acc)
            })?)
    }

    pub fn can_user_act(&self, uuid: MemberId) -> bool {
        self.admins.contains(&uuid)
    }

    /// Add new members to the conversation
    /// Note: this is not exposed publicly because authorization isn't handled at this level
    pub(crate) fn add_members(
        &self,
        members: &mut [ConversationMember],
        backend: &MlsCryptoProvider,
    ) -> CryptoResult<MlsConversationCreationMessage> {
        let keypackages = members
            .iter_mut()
            .flat_map(|member| member.keypackages_for_all_clients())
            .filter_map(|(_, kps)| kps)
            .collect::<Vec<openmls::prelude::KeyPackage>>();

        let (message, welcome) = self
            .group
            .write()
            .map_err(|_| CryptoError::LockPoisonError)?
            .add_members(backend, &keypackages)
            .map_err(MlsError::from)?;

        if self
            .group
            .read()
            .map_err(|_| CryptoError::LockPoisonError)?
            .state_changed()
            == openmls::group::InnerState::Changed
        {
            let mut buf = vec![];
            self.group
                .write()
                .map_err(|_| CryptoError::LockPoisonError)?
                .save(&mut buf)?;
            backend.key_store().mls_group_persist(&self.id, &buf)?;
        }

        Ok(MlsConversationCreationMessage { welcome, message })
    }

    /// Remove members from the conversation
    /// Note: this is not exposed publicly because authorization isn't handled at this level
    pub(crate) fn remove_members(
        &self,
        members: &[ConversationMember],
        backend: &MlsCryptoProvider,
    ) -> CryptoResult<MlsMessageOut> {
        let clients = members.iter().flat_map(|m| m.clients()).collect::<Vec<&ClientId>>();
        let crypto = backend.crypto();

        let member_kps = self
            .group
            .read()
            .map_err(|_| CryptoError::LockPoisonError)?
            .members()
            .into_iter()
            .filter(|kp| {
                clients
                    .iter()
                    .any(|client_id| client_id.as_slice() == kp.credential().identity())
            })
            .try_fold(Vec::new(), |mut acc, kp| -> CryptoResult<Vec<KeyPackageRef>> {
                acc.push(kp.hash_ref(crypto).map_err(MlsError::from)?);
                Ok(acc)
            })?;

        let (message, _) = self
            .group
            .write()
            .map_err(|_| CryptoError::LockPoisonError)?
            .remove_members(backend, &member_kps)
            .map_err(MlsError::from)?;

        if self
            .group
            .read()
            .map_err(|_| CryptoError::LockPoisonError)?
            .state_changed()
            == openmls::group::InnerState::Changed
        {
            let mut buf = vec![];
            self.group
                .write()
                .map_err(|_| CryptoError::LockPoisonError)?
                .save(&mut buf)?;
            backend.key_store().mls_group_persist(&self.id, &buf)?;
        }

        Ok(message)
    }

    pub fn decrypt_message<M: AsRef<[u8]>>(
        &self,
        message: M,
        backend: &MlsCryptoProvider,
    ) -> CryptoResult<Option<Vec<u8>>> {
        let msg_in = openmls::framing::MlsMessageIn::try_from_bytes(message.as_ref()).map_err(MlsError::from)?;

        let mut group = self.group.write().map_err(|_| CryptoError::LockPoisonError)?;
        let parsed_message = group.parse_message(msg_in, backend).map_err(MlsError::from)?;

        let message = group
            .process_unverified_message(parsed_message, None, backend)
            .map_err(MlsError::from)?;

        match message {
            ProcessedMessage::ApplicationMessage(app_msg) => {
                return Ok(Some(app_msg.into_bytes()));
            }
            ProcessedMessage::ProposalMessage(proposal) => {
                group.store_pending_proposal(*proposal);
            }
            ProcessedMessage::StagedCommitMessage(staged_commit) => {
                group.merge_staged_commit(*staged_commit).map_err(MlsError::from)?;
            }
        }

        if group.state_changed() == openmls::group::InnerState::Changed {
            let mut buf = vec![];
            group.save(&mut buf)?;
            backend.key_store().mls_group_persist(&self.id, &buf)?;
        }

        Ok(None)
    }

    pub fn encrypt_message<M: AsRef<[u8]>>(&self, message: M, backend: &MlsCryptoProvider) -> CryptoResult<Vec<u8>> {
        let message = self
            .group
            .write()
            .map_err(|_| CryptoError::LockPoisonError)?
            .create_message(backend, message.as_ref())
            .map_err(MlsError::from)?;

        Ok(message.to_bytes().map_err(MlsError::from)?)
    }

    pub fn reinit(&self, backend: &MlsCryptoProvider) -> CryptoResult<MlsConversationReinitMessage> {
        Ok(self
            .group
            .write()
            .map_err(|_| CryptoError::LockPoisonError)?
            .self_update(backend, None)
            .map_err(MlsError::from)
            .map(|(message, welcome)| MlsConversationReinitMessage { welcome, message })?)
    }
}

#[cfg(test)]
mod tests {
    use super::{ConversationId, MlsConversation, MlsConversationConfiguration};
    use crate::conversation::Client;
    use crate::{member::ConversationMember, prelude::MlsConversationCreationMessage};
    use mls_crypto_provider::MlsCryptoProvider;

    #[inline(always)]
    fn init_keystore(identifier: &str) -> MlsCryptoProvider {
        let backend = MlsCryptoProvider::try_new_in_memory(identifier).unwrap();
        backend
    }

    #[test]
    fn can_create_self_conversation() {
        let mut backend = init_keystore("self");
        let mut alice = Client::random_generate(&backend).unwrap();

        let uuid = uuid::Uuid::new_v4();
        let conversation_id = ConversationId::from(format!("{}@conversations.wire.com", uuid.hyphenated()).as_bytes());

        let (alice_group, conversation_creation_message) = MlsConversation::create(
            conversation_id.clone(),
            &mut alice,
            MlsConversationConfiguration::builder().build().unwrap(),
            &mut backend,
        )
        .unwrap();

        assert!(conversation_creation_message.is_none());
        assert_eq!(alice_group.id, conversation_id);
        assert_eq!(alice_group.group.read().unwrap().group_id().as_slice(), conversation_id);

        assert_eq!(alice_group.members().unwrap().len(), 1);
    }

    #[test]
    fn can_create_1_1_conversation() {
        let mut alice_backend = init_keystore("alice");
        let bob_backend = init_keystore("bob");
        let mut alice = Client::random_generate(&alice_backend).unwrap();
        let bob = ConversationMember::random_generate(&bob_backend).unwrap();

        let uuid = uuid::Uuid::new_v4();
        let conversation_id = ConversationId::from(format!("{}@conversations.wire.com", uuid.hyphenated()));

        let conversation_config = MlsConversationConfiguration::builder()
            .extra_members(vec![bob])
            .build()
            .unwrap();

        let (alice_group, conversation_creation_message) = MlsConversation::create(
            conversation_id.clone(),
            &mut alice,
            conversation_config.clone(),
            &mut alice_backend,
        )
        .unwrap();

        assert!(conversation_creation_message.is_some());
        assert_eq!(alice_group.id, conversation_id);
        assert_eq!(alice_group.group.read().unwrap().group_id().as_slice(), conversation_id);
        assert_eq!(alice_group.members().unwrap().len(), 2);

        let MlsConversationCreationMessage { welcome, .. } = conversation_creation_message.unwrap();

        assert!(MlsConversation::from_welcome_message(welcome, conversation_config, &bob_backend).is_ok());
    }

    #[test]
    fn can_create_100_people_conversation() {
        let mut alice_backend = init_keystore("alice");
        let mut alice = Client::random_generate(&alice_backend).unwrap();

        let bob_and_friends = (0..99).fold(Vec::with_capacity(100), |mut acc, _| {
            let uuid = uuid::Uuid::new_v4();
            let backend = init_keystore(&uuid.hyphenated().to_string());

            let member = ConversationMember::random_generate(&backend).unwrap();
            acc.push((backend, member));
            acc
        });

        let number_of_friends = bob_and_friends.len();

        let uuid = uuid::Uuid::new_v4();
        let conversation_id = ConversationId::from(format!("{}@conversations.wire.com", uuid.hyphenated()));

        let conversation_config = MlsConversationConfiguration::builder()
            .extra_members(bob_and_friends.iter().map(|(_, m)| m.clone()).collect())
            .build()
            .unwrap();

        let (alice_group, conversation_creation_message) = MlsConversation::create(
            conversation_id.clone(),
            &mut alice,
            conversation_config.clone(),
            &mut alice_backend,
        )
        .unwrap();

        assert!(conversation_creation_message.is_some());
        assert_eq!(alice_group.id, conversation_id);
        assert_eq!(alice_group.group.read().unwrap().group_id().as_slice(), conversation_id);
        assert_eq!(alice_group.members().unwrap().len(), 1 + number_of_friends);

        let MlsConversationCreationMessage { welcome, .. } = conversation_creation_message.unwrap();

        let bob_and_friends_groups: Vec<MlsConversation> = bob_and_friends
            .iter()
            .map(|(backend, _)| {
                MlsConversation::from_welcome_message(welcome.clone(), conversation_config.clone(), &backend).unwrap()
            })
            .collect();

        assert_eq!(bob_and_friends_groups.len(), 99);
    }

    #[test]
    fn can_roundtrip_message_in_1_1_conversation() {
        let mut alice_backend = init_keystore("alice");
        let bob_backend = init_keystore("bob");

        let mut alice = Client::random_generate(&alice_backend).unwrap();
        let bob = ConversationMember::random_generate(&bob_backend).unwrap();

        let uuid = uuid::Uuid::new_v4();
        let conversation_id = ConversationId::from(format!("{}@conversations.wire.com", uuid.hyphenated()));

        let configuration = MlsConversationConfiguration::builder()
            .extra_members(vec![bob])
            .build()
            .unwrap();

        let (alice_group, conversation_creation_message) =
            MlsConversation::create(conversation_id.clone(), &mut alice, configuration, &mut alice_backend).unwrap();

        assert!(conversation_creation_message.is_some());
        assert_eq!(alice_group.id, conversation_id);
        assert_eq!(alice_group.group.read().unwrap().group_id().as_slice(), conversation_id);
        assert_eq!(alice_group.members().unwrap().len(), 2);

        let MlsConversationCreationMessage { welcome, .. } = conversation_creation_message.unwrap();

        let bob_group = MlsConversation::from_welcome_message(
            welcome,
            MlsConversationConfiguration::builder().build().unwrap(),
            &bob_backend,
        )
        .unwrap();

        let original_message = b"Hello World!";

        let encrypted_message = alice_group.encrypt_message(original_message, &alice_backend).unwrap();
        let roundtripped_message = bob_group
            .decrypt_message(&encrypted_message, &bob_backend)
            .unwrap()
            .unwrap();
        assert_eq!(original_message, roundtripped_message.as_slice());
        let encrypted_message = bob_group.encrypt_message(roundtripped_message, &bob_backend).unwrap();
        let roundtripped_message = alice_group
            .decrypt_message(&encrypted_message, &alice_backend)
            .unwrap()
            .unwrap();
        assert_eq!(original_message, roundtripped_message.as_slice());
    }
}
