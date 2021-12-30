use mls_crypto_provider::MlsCryptoProvider;
use openmls::{prelude::KeyPackage, group::MlsGroup, messages::Welcome, framing::MlsMessageOut};

use crate::{CryptoResult, MlsError, identifiers::ZeroKnowledgeUuid};


pub type ConversationId = ZeroKnowledgeUuid;

#[derive(Debug, Default)]
pub struct MlsConversationConfiguration {
    pub(crate) init_keys: Vec<KeyPackage>,
    pub(crate) admins: Vec<ZeroKnowledgeUuid>,
    // FIXME: No way to configure ciphersuites.
    // FIXME: Can maybe only check it against the supported ciphersuites in the group afterwards?
    // TODO: Maybe pull CiphersuiteName from OpenMLS
    pub(crate) _ciphersuite: (),
    // FIXME: openmls::group::config::UpdatePolicy is NOT configurable at the moment.
    // FIXME: None of the fields are available and there are no ways to build it/mutate it
    // TODO: Implement the key rotation manually instead.
    // TODO: Define if the rotation span is per X messages or per X epochs or even per X time interval
    pub(crate) _key_rotation_span: (),
}

// impl Into<openmls::group::MlsGroupConfig> for MlsConversationConfiguration {
//     fn into(self) -> openmls::group::MlsGroupConfig {
//         let mls_group_config = openmls::group::MlsGroupConfig::builder()
//             .wire_format(openmls::framing::WireFormat::MlsCiphertext)
//             // .padding_size(0) TODO: Understand what it does and define a safe value
//             // .max_past_epochs(5) TODO: Understand what it does and define a safe value
//             // .number_of_resumtion_secrets(0) TODO: Understand what it does and define a safe value
//             // .use_ratchet_tree_extension(false) TODO: Understand what it does and define a safe value
//             .build();

//         mls_group_config
//     }
// }

#[derive(Debug)]
pub struct MlsConversation {
    pub(crate) id: ConversationId,
    pub(crate) group: MlsGroup,
    pub(crate) admins: Vec<ZeroKnowledgeUuid>,
}

#[derive(Debug)]
pub struct MlsConversationCreationMessage {
    pub welcome: Welcome,
    pub message: MlsMessageOut,
}

impl MlsConversation {
    pub fn create(
        id: ConversationId,
        config: MlsConversationConfiguration,
        backend: &MlsCryptoProvider,
    ) -> CryptoResult<(Self, Option<MlsConversationCreationMessage>)> {
        let mls_group_config = openmls::group::MlsGroupConfig::default();
        let mut group = MlsGroup::new(
            backend,
            &mls_group_config,
            openmls::group::GroupId::from_slice(id.as_bytes()),
            &[],
        )
        .map_err(MlsError::from)?;

        let mut maybe_creation_message = None;
        if config.init_keys.len() > 0 {
            let (message, welcome) = group.add_members(backend, &config.init_keys).map_err(MlsError::from)?;
            maybe_creation_message = Some(MlsConversationCreationMessage {
                message,
                welcome,
            });
        }

        let conversation = Self {
            id,
            group,
            admins: config.admins,
        };

        Ok((conversation, maybe_creation_message))
    }

    pub fn id(&self) -> ConversationId {
        self.id
    }

    pub fn can_user_act(&self, uuid: ZeroKnowledgeUuid) -> bool {
        self.admins.contains(&uuid)
    }
}
