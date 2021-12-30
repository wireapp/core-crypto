mod error;
pub use self::error::*;

use std::collections::HashMap;

pub type ConversationId = uuid::Uuid;

#[repr(C)]
#[derive(Debug, Default)]
pub struct MlsConversationConfiguration {
    pub(crate) init_keys: Vec<Vec<u8>>,
    pub(crate) admins: Vec<uuid::Uuid>,
    // FIXME: No way to configure ciphersuites.
    // FIXME: Can maybe only check it against the supported ciphersuites in the group afterwards?
    pub(crate) ciphersuite: (),
    // FIXME: openmls::group::config::UpdatePolicy is NOT configurable at the moment.
    // FIXME: None of the fields are available and there are no way to build it/mutate it
    pub(crate) key_rotation_span: (),
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

#[allow(dead_code)]
#[derive(Debug)]
pub struct MlsCentral {
    configuration: MlsConversationConfiguration,
    mls_backend: mls_crypto_provider::MlsCryptoProvider,
    mls_groups: HashMap<ConversationId, openmls::group::MlsGroup>,
}

impl MlsCentral {
    pub fn try_new<S: AsRef<str>>(
        store_path: S,
        identity_key: S,
    ) -> crate::error::CryptoResult<Self> {
        let mls_backend =
            mls_crypto_provider::MlsCryptoProvider::try_new(store_path, identity_key)?;

        Ok(Self {
            configuration: Default::default(),
            mls_backend,
            mls_groups: Default::default(),
        })
    }

    pub fn new_conversation(
        &mut self,
        id: ConversationId,
        _config: MlsConversationConfiguration,
    ) -> crate::error::CryptoResult<()> {
        let group = openmls::group::MlsGroup::new(
            &self.mls_backend,
            &openmls::group::MlsGroupConfig::default(),
            openmls::group::GroupId::from_slice(id.as_bytes()),
            &[],
        )
        .map_err(MlsError::from)?;

        self.mls_groups.insert(id, group);

        Ok(())
    }

    pub fn encrypt_message<M: AsRef<[u8]>>(
        &mut self,
        conversation: ConversationId,
        message: M,
    ) -> CryptoResult<Vec<u8>> {
        let group = self
            .mls_groups
            .get_mut(&conversation)
            .ok_or(CryptoError::ConversationNotFound(conversation))?;

        use openmls::prelude::{TlsSerializeTrait as _, TlsSizeTrait as _};

        let message = group
            .create_message(&self.mls_backend, message.as_ref())
            .map_err(crate::MlsError::from)?;
        let mut buf = Vec::with_capacity(message.tls_serialized_len());
        // TODO: Define serialization format? Probably won't be the TLS thingy?
        message
            .tls_serialize(&mut buf)
            .map_err(openmls::prelude::MlsCiphertextError::from)
            .map_err(MlsError::from)?;

        Ok(buf)
    }

    pub fn decrypt_message<M: std::io::Read>(
        &mut self,
        conversation: ConversationId,
        message: &mut M,
    ) -> CryptoResult<Vec<u8>> {
        use openmls::prelude::TlsDeserializeTrait as _;

        let raw_msg = openmls::framing::MlsCiphertext::tls_deserialize(message)
            .map_err(openmls::prelude::MlsCiphertextError::from)
            .map_err(MlsError::from)?;

        let group = self
            .mls_groups
            .get_mut(&conversation)
            .ok_or(CryptoError::ConversationNotFound(conversation))?;

        let msg_in = openmls::framing::MlsMessageIn::Ciphertext(Box::new(raw_msg));

        let parsed_message = group
            .parse_message(msg_in, &self.mls_backend)
            .map_err(MlsError::from)?;

        let message = group
            .process_unverified_message(parsed_message, None, &self.mls_backend)
            .map_err(MlsError::from)?;

        match message {
            openmls::framing::ProcessedMessage::ApplicationMessage(app_msg) => {
                return Ok(app_msg.message().into());
            },
            openmls::framing::ProcessedMessage::ProposalMessage(proposal) => {
                let _leaf_index = proposal.sender().to_leaf_index();

                // FIXME: Indexed members isn't pub? How to check authentication?
                // for (index, keypackage) in group.indexed_members()? {
                //     if index == leaf_index {
                //         if let Some(ext) = keypackage.extensions().iter().find(|e| e.as_capabilities_extension().ok()) {
                //         }
                //         break;
                //     }
                // }
            },
            openmls::framing::ProcessedMessage::StagedCommitMessage(_staged_commit) => {
                //group.merge_staged_commit(*staged_commit).map_err(MlsError::from)?;
            },
        }

        todo!()
    }
}
