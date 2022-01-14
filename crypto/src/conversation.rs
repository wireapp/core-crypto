use mls_crypto_provider::MlsCryptoProvider;
use openmls::{framing::MlsMessageOut, group::MlsGroup, messages::Welcome, prelude::KeyPackage};

use crate::{
    member::{ConversationMember, MemberId},
    client::Client,
    CryptoResult, MlsError,
};

// TODO: KISS
#[cfg(not(debug_assertions))]
pub type ConversationId = crate::identifiers::ZeroKnowledgeUuid;
#[cfg(debug_assertions)]
pub type ConversationId = crate::identifiers::QualifiedUuid;

// FIXME: This is utterly broken and wouldn't pass FFI
#[derive(Debug, derive_builder::Builder)]
#[builder(pattern = "owned")]
#[allow(dead_code)]
pub struct MlsConversationConfiguration {
    pub author: Client,
    #[builder(default)]
    pub extra_members: Vec<ConversationMember>,
    #[builder(default)]
    pub admins: Vec<MemberId>,
    // FIXME: No way to configure ciphersuites.
    // FIXME: Can maybe only check it against the supported ciphersuites in the group afterwards?
    // TODO: Maybe pull CiphersuiteName from OpenMLS
    #[builder(default)]
    pub ciphersuite: Option<String>,
    // FIXME: openmls::group::config::UpdatePolicy is NOT configurable at the moment.
    // FIXME: None of the fields are available and there are no ways to build it/mutate it
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
            // Ciphertext only!
            .wire_format(openmls::framing::WireFormat::MlsCiphertext)
            // TODO: Understand what it does and define a safe value
            // .padding_size(0)
            // TODO: Understand what it does and define a safe value
            // .max_past_epochs(5)
            // TODO: Understand what it does and define a safe value
            // .number_of_resumption_secrets(0)
            // ! Make sure our DS *does* distribute copies of the group's ratchet tree
            // ! If yes, we can set it to false, otherwise, set it to true
            .use_ratchet_tree_extension(true)
            .build()
    }
}

#[derive(Debug)]
#[allow(dead_code)]
pub struct MlsConversation {
    pub(crate) id: ConversationId,
    pub(crate) group: parking_lot::RwLock<MlsGroup>,
    pub(crate) admins: Vec<MemberId>,
    configuration: MlsConversationConfiguration,
}

#[derive(Debug)]
pub struct MlsConversationCreationMessage {
    pub welcome: Welcome,
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

        let msg = self.message.to_bytes().map_err(MlsError::from)?;

        Ok((welcome, msg))
    }
}

impl MlsConversation {
    pub fn create(
        id: ConversationId,
        mut config: MlsConversationConfiguration,
        backend: &MlsCryptoProvider,
    ) -> CryptoResult<(Self, Option<MlsConversationCreationMessage>)> {
        let mls_group_config = MlsConversationConfiguration::openmls_default_configuration();
        let mut group = MlsGroup::new(
            backend,
            &mls_group_config,
            openmls::group::GroupId::from_slice(id.to_string().as_bytes()),
            &config.author.keypackage_hash(backend)?,
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

    pub fn members(&self) -> CryptoResult<std::collections::HashMap<MemberId, openmls::credentials::Credential>> {
        let mut ret = std::collections::HashMap::default();

        for c in self.group.read().members().map_err(MlsError::from)? {
            let identity_str = std::str::from_utf8(c.identity())?;
            ret.insert(identity_str.parse()?, c.clone());
        }
        Ok(ret)
    }

    pub fn can_user_act(&self, uuid: MemberId) -> bool {
        self.admins.contains(&uuid)
    }

    pub fn decrypt_message<M: AsRef<[u8]>>(&self, message: M, backend: &MlsCryptoProvider) -> CryptoResult<Vec<u8>> {
        let msg_in = openmls::framing::MlsMessageIn::try_from_bytes(message.as_ref()).map_err(MlsError::from)?;

        let mut group = self.group.write();
        let parsed_message = group.parse_message(msg_in, backend).map_err(MlsError::from)?;

        let message = group
            .process_unverified_message(parsed_message, None, backend)
            .map_err(MlsError::from)?;

        if let openmls::framing::ProcessedMessage::ApplicationMessage(app_msg) = message {
            let (buf, _sender) = app_msg.into_parts();
            Ok(buf)
        } else {
            unimplemented!(
                "Types of messages other than ProcessedMessage::ApplicationMessage aren't supported just yet"
            )
        }
    }

    pub fn encrypt_message<M: AsRef<[u8]>>(&self, message: M, backend: &MlsCryptoProvider) -> CryptoResult<Vec<u8>> {
        let message = self
            .group
            .write()
            .create_message(backend, message.as_ref())
            .map_err(crate::MlsError::from)?;

        Ok(message.to_bytes().map_err(MlsError::from)?)
    }
}

#[cfg(test)]
mod tests {
    use crate::conversation::Client;
    use super::{ConversationId, MlsConversation, MlsConversationConfiguration};
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
        let alice = Client::random_generate(&backend).unwrap();

        let uuid = uuid::Uuid::new_v4();
        let conversation_id =
            ConversationId::from_str(&format!("{}@conversations.wire.com", uuid.to_hyphenated())).unwrap();

        let (alice_group, conversation_creation_message) = MlsConversation::create(
            conversation_id.clone(),
            MlsConversationConfiguration::builder().author(alice).build().unwrap(),
            &mut backend,
        )
        .unwrap();

        assert!(conversation_creation_message.is_none());
        assert_eq!(alice_group.id, conversation_id);
        assert_eq!(
            alice_group.group.read().group_id().as_slice(),
            conversation_id.to_string().as_bytes()
        );

        assert_eq!(alice_group.members().unwrap().len(), 1);
    }

    #[test]
    fn can_create_1_1_conversation() {
        let mut backend = init_keystore();
        let alice = Client::random_generate(&backend).unwrap();
        let bob = ConversationMember::random_generate(&backend).unwrap();

        let uuid = uuid::Uuid::new_v4();
        let conversation_id =
            ConversationId::from_str(&format!("{}@conversations.wire.com", uuid.to_hyphenated())).unwrap();

        let conversation_config = MlsConversationConfiguration::builder()
            .author(alice)
            .extra_members(vec![bob])
            .build()
            .unwrap();

        let (alice_group, conversation_creation_message) =
            MlsConversation::create(conversation_id.clone(), conversation_config, &mut backend).unwrap();

        assert!(conversation_creation_message.is_some());
        assert_eq!(alice_group.id, conversation_id);
        assert_eq!(
            alice_group.group.read().group_id().as_slice(),
            conversation_id.to_string().as_bytes()
        );
        assert_eq!(alice_group.members().unwrap().len(), 2);

        let MlsConversationCreationMessage { welcome, .. } = conversation_creation_message.unwrap();

        assert!(MlsConversation::from_welcome_message(welcome, conversation_config, &backend).is_ok());
    }

    #[test]
    fn can_create_100_people_conversation() {
        let mut backend = init_keystore();
        let alice = Client::random_generate(&backend).unwrap();

        let bob_and_friends = (0..99).fold(Vec::with_capacity(100), |mut acc, _| {
            let member = ConversationMember::random_generate(&backend).unwrap();
            acc.push(member);
            acc
        });

        let number_of_friends = bob_and_friends.len();

        let uuid = uuid::Uuid::new_v4();
        let conversation_id =
            ConversationId::from_str(&format!("{}@conversations.wire.com", uuid.to_hyphenated())).unwrap();

        let conversation_config = MlsConversationConfiguration::builder()
            .author(alice)
            .extra_members(bob_and_friends)
            .build()
            .unwrap();

        let (alice_group, conversation_creation_message) =
            MlsConversation::create(conversation_id.clone(), conversation_config, &mut backend).unwrap();

        assert!(conversation_creation_message.is_some());
        assert_eq!(alice_group.id, conversation_id);
        assert_eq!(
            alice_group.group.read().group_id().as_slice(),
            conversation_id.to_string().as_bytes()
        );
        assert_eq!(alice_group.members().unwrap().len(), 1 + number_of_friends);

        let MlsConversationCreationMessage { welcome, .. } = conversation_creation_message.unwrap();

        let bob_and_friends_groups: Vec<MlsConversation> = bob_and_friends
            .iter()
            .map(|_| {
                MlsConversation::from_welcome_message(welcome.clone(), conversation_config, &backend).unwrap()
            })
            .collect();

        assert_eq!(bob_and_friends_groups.len(), 99);
    }

    #[test]
    fn can_roundtrip_message_in_1_1_conversation() {
        let mut backend = init_keystore();
        let alice = Client::random_generate(&backend).unwrap();

        let bob = ConversationMember::random_generate(&backend).unwrap();

        let uuid = uuid::Uuid::new_v4();
        let conversation_id =
            ConversationId::from_str(&format!("{}@conversations.wire.com", uuid.to_hyphenated())).unwrap();

        let configuration = MlsConversationConfiguration::builder()
            .author(alice)
            .extra_members(vec![bob])
            .build()
            .unwrap();

        let (mut alice_group, conversation_creation_message) =
            MlsConversation::create(conversation_id.clone(), configuration, &mut backend).unwrap();

        assert!(conversation_creation_message.is_some());
        assert_eq!(alice_group.id, conversation_id);
        assert_eq!(
            alice_group.group.read().group_id().as_slice(),
            conversation_id.to_string().as_bytes()
        );
        assert_eq!(alice_group.members().unwrap().len(), 2);

        let MlsConversationCreationMessage { welcome, .. } = conversation_creation_message.unwrap();

        let mut bob_group = MlsConversation::from_welcome_message(welcome, configuration, &backend).unwrap();

        let original_message = b"Hello World!";

        let encrypted_message = alice_group.encrypt_message(original_message, &backend).unwrap();
        let roundtripped_message = bob_group.decrypt_message(&encrypted_message, &backend).unwrap();
        assert_eq!(original_message, roundtripped_message.as_slice());
        let encrypted_message = bob_group.encrypt_message(roundtripped_message, &backend).unwrap();
        let roundtripped_message = alice_group.decrypt_message(&encrypted_message, &backend).unwrap();
        assert_eq!(original_message, roundtripped_message.as_slice());
    }
}
