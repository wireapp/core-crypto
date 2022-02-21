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

use mls_crypto_provider::MlsCryptoProvider;
use openmls::{
    ciphersuite::ciphersuites::CiphersuiteName,
    framing::{MlsMessageOut, ProcessedMessage},
    group::MlsGroup,
    messages::Welcome,
    prelude::{KeyPackage, SenderRatchetConfiguration},
};

use crate::{
    client::Client,
    member::{ConversationMember, MemberId},
    CryptoError, CryptoResult, MlsError,
};

// #[cfg(not(debug_assertions))]
// pub type ConversationId = crate::identifiers::ZeroKnowledgeUuid;
// #[cfg(debug_assertions)]
pub type ConversationId = crate::identifiers::QualifiedUuid;

#[derive(Debug, Clone, derive_builder::Builder)]
pub struct MlsConversationConfiguration {
    #[builder(default)]
    pub extra_members: Vec<ConversationMember>,
    #[builder(default)]
    pub admins: Vec<MemberId>,
    #[builder(default)]
    pub ciphersuite: CiphersuiteName,
    // TODO: Implement the key rotation manually instead.
    // TODO: Define if the rotation span is per X messages or per X epochs or even per X time interval
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
            .wire_format_policy(openmls::group::WireFormatPolicy::new(
                openmls::group::OutgoingWireFormatPolicy::AlwaysCiphertext,
                openmls::group::IncomingWireFormatPolicy::AlwaysCiphertext,
            ))
            .max_past_epochs(3)
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
        let welcome = self
            .welcome
            .tls_serialize_detached()
            .map_err(openmls::prelude::WelcomeError::from)
            .map_err(MlsError::from)?;

        let msg = self
            .message
            .to_bytes()
            // FIXME: Remove this when it's fixed MLS-side
            .map_err(|e| openmls::error::ErrorString::from(e.to_string()))
            .map_err(MlsError::from)?;

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
            openmls::group::GroupId::from_slice(id.to_string().as_bytes()),
            &author_client.keypackage_hash(backend)?,
        )
        .map_err(MlsError::from)?;

        let mut maybe_creation_message = None;
        if !config.extra_members.is_empty() {
            let kps: Vec<KeyPackage> = config
                .extra_members
                .iter()
                .map(|m| m.current_keypackage().clone())
                .collect();

            let (message, welcome) = group.add_members(backend, &kps).map_err(MlsError::from)?;

            group.merge_pending_commit().map_err(MlsError::from)?;

            maybe_creation_message = Some(MlsConversationCreationMessage { message, welcome });
        }

        let conversation = Self {
            id,
            group: group.into(),
            admins: config.admins.clone(),
            configuration: config,
        };

        Ok((conversation, maybe_creation_message))
    }

    // FIXME: Do we need to provide the ratchet_tree to the MlsGroup? Does everything crumble down if we can't actually get it?
    pub fn from_welcome_message(
        welcome: Welcome,
        configuration: MlsConversationConfiguration,
        backend: &MlsCryptoProvider,
    ) -> CryptoResult<Self> {
        let mls_group_config = MlsConversationConfiguration::openmls_default_configuration();
        let group = MlsGroup::new_from_welcome(backend, &mls_group_config, welcome, None).map_err(MlsError::from)?;

        Ok(Self {
            id: ConversationId::try_from(group.group_id().as_slice())?,
            // FIXME: There's currently no way to retrieve who's admin and who's not.
            // ? Add custom extension to the group?
            // ? Get this data from the DS?
            admins: configuration.admins.clone(),
            group: group.into(),
            configuration,
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
            .map_err(MlsError::from)?
            .iter()
            .try_fold(std::collections::HashMap::new(), |mut acc, kp| -> CryptoResult<_> {
                let credential = kp.credential();
                let identity_str = std::str::from_utf8(credential.identity())?;
                let client_id: crate::client::ClientId = identity_str.parse()?;
                let member_id: MemberId = client_id.into();
                acc.entry(member_id)
                    .or_insert_with(|| vec![])
                    .push((*credential).clone());

                Ok(acc)
            })?)
    }

    pub fn can_user_act(&self, uuid: MemberId) -> bool {
        self.admins.contains(&uuid)
    }

    pub fn decrypt_message<M: AsRef<[u8]>>(
        &self,
        message: M,
        backend: &MlsCryptoProvider,
    ) -> CryptoResult<Option<Vec<u8>>> {
        let msg_in = openmls::framing::MlsMessageIn::try_from_bytes(message.as_ref())
            // FIXME: Remove this when it's fixed MLS-side
            .map_err(|e| openmls::error::ErrorString::from(e.to_string()))
            .map_err(MlsError::from)?;

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

        Ok(None)
    }

    pub fn encrypt_message<M: AsRef<[u8]>>(&self, message: M, backend: &MlsCryptoProvider) -> CryptoResult<Vec<u8>> {
        let message = self
            .group
            .write()
            .map_err(|_| CryptoError::LockPoisonError)?
            .create_message(backend, message.as_ref())
            .map_err(MlsError::from)?;

        Ok(message.to_bytes()
            // FIXME: Remove this when it's fixed MLS-side
            .map_err(|e| openmls::error::ErrorString::from(e.to_string()))
            .map_err(MlsError::from)?)
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
    use std::str::FromStr as _;

    #[inline(always)]
    fn init_keystore() -> MlsCryptoProvider {
        let backend = MlsCryptoProvider::try_new_in_memory("test").unwrap();
        backend
    }

    #[test]
    fn can_create_self_conversation() {
        let mut backend = init_keystore();
        let mut alice = Client::random_generate(&backend).unwrap();

        let uuid = uuid::Uuid::new_v4();
        let conversation_id =
            ConversationId::from_str(&format!("{}@conversations.wire.com", uuid.hyphenated())).unwrap();

        let (alice_group, conversation_creation_message) = MlsConversation::create(
            conversation_id.clone(),
            &mut alice,
            MlsConversationConfiguration::builder().build().unwrap(),
            &mut backend,
        )
        .unwrap();

        assert!(conversation_creation_message.is_none());
        assert_eq!(alice_group.id, conversation_id);
        assert_eq!(
            alice_group.group.read().unwrap().group_id().as_slice(),
            conversation_id.to_string().as_bytes()
        );

        assert_eq!(alice_group.members().unwrap().len(), 1);
    }

    #[test]
    fn can_create_1_1_conversation() {
        let mut backend = init_keystore();
        let mut alice = Client::random_generate(&backend).unwrap();
        let bob = ConversationMember::random_generate(&backend).unwrap();

        let uuid = uuid::Uuid::new_v4();
        let conversation_id =
            ConversationId::from_str(&format!("{}@conversations.wire.com", uuid.hyphenated())).unwrap();

        let conversation_config = MlsConversationConfiguration::builder()
            .extra_members(vec![bob])
            .build()
            .unwrap();

        let (alice_group, conversation_creation_message) = MlsConversation::create(
            conversation_id.clone(),
            &mut alice,
            conversation_config.clone(),
            &mut backend,
        )
        .unwrap();

        assert!(conversation_creation_message.is_some());
        assert_eq!(alice_group.id, conversation_id);
        assert_eq!(
            alice_group.group.read().unwrap().group_id().as_slice(),
            conversation_id.to_string().as_bytes()
        );
        assert_eq!(alice_group.members().unwrap().len(), 2);

        let MlsConversationCreationMessage { welcome, .. } = conversation_creation_message.unwrap();

        assert!(MlsConversation::from_welcome_message(welcome, conversation_config, &backend).is_ok());
    }

    #[test]
    fn can_create_100_people_conversation() {
        let mut backend = init_keystore();
        let mut alice = Client::random_generate(&backend).unwrap();

        let bob_and_friends = (0..99).fold(Vec::with_capacity(100), |mut acc, _| {
            let member = ConversationMember::random_generate(&backend).unwrap();
            acc.push(member);
            acc
        });

        let number_of_friends = bob_and_friends.len();

        let uuid = uuid::Uuid::new_v4();
        let conversation_id =
            ConversationId::from_str(&format!("{}@conversations.wire.com", uuid.hyphenated())).unwrap();

        let conversation_config = MlsConversationConfiguration::builder()
            .extra_members(bob_and_friends.clone())
            .build()
            .unwrap();

        let (alice_group, conversation_creation_message) = MlsConversation::create(
            conversation_id.clone(),
            &mut alice,
            conversation_config.clone(),
            &mut backend,
        )
        .unwrap();

        assert!(conversation_creation_message.is_some());
        assert_eq!(alice_group.id, conversation_id);
        assert_eq!(
            alice_group.group.read().unwrap().group_id().as_slice(),
            conversation_id.to_string().as_bytes()
        );
        assert_eq!(alice_group.members().unwrap().len(), 1 + number_of_friends);

        let MlsConversationCreationMessage { welcome, .. } = conversation_creation_message.unwrap();

        let bob_and_friends_groups: Vec<MlsConversation> = bob_and_friends
            .iter()
            .map(|_| {
                MlsConversation::from_welcome_message(welcome.clone(), conversation_config.clone(), &backend).unwrap()
            })
            .collect();

        assert_eq!(bob_and_friends_groups.len(), 99);
    }

    #[test]
    fn can_roundtrip_message_in_1_1_conversation() {
        let mut backend = init_keystore();
        let mut alice = Client::random_generate(&backend).unwrap();

        let bob = ConversationMember::random_generate(&backend).unwrap();

        let uuid = uuid::Uuid::new_v4();
        let conversation_id =
            ConversationId::from_str(&format!("{}@conversations.wire.com", uuid.hyphenated())).unwrap();

        let configuration = MlsConversationConfiguration::builder()
            .extra_members(vec![bob])
            .build()
            .unwrap();

        let (alice_group, conversation_creation_message) =
            MlsConversation::create(conversation_id.clone(), &mut alice, configuration, &mut backend).unwrap();

        assert!(conversation_creation_message.is_some());
        assert_eq!(alice_group.id, conversation_id);
        assert_eq!(
            alice_group.group.read().unwrap().group_id().as_slice(),
            conversation_id.to_string().as_bytes()
        );
        assert_eq!(alice_group.members().unwrap().len(), 2);

        let MlsConversationCreationMessage { welcome, .. } = conversation_creation_message.unwrap();

        let bob_group = MlsConversation::from_welcome_message(
            welcome,
            MlsConversationConfiguration::builder().build().unwrap(),
            &backend,
        )
        .unwrap();

        let original_message = b"Hello World!";

        let encrypted_message = alice_group.encrypt_message(original_message, &backend).unwrap();
        let roundtripped_message = bob_group
            .decrypt_message(&encrypted_message, &backend)
            .unwrap()
            .unwrap();
        assert_eq!(original_message, roundtripped_message.as_slice());
        let encrypted_message = bob_group.encrypt_message(roundtripped_message, &backend).unwrap();
        let roundtripped_message = alice_group
            .decrypt_message(&encrypted_message, &backend)
            .unwrap()
            .unwrap();
        assert_eq!(original_message, roundtripped_message.as_slice());
    }
}
