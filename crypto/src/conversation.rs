use mls_crypto_provider::MlsCryptoProvider;
use openmls::{framing::MlsMessageOut, group::MlsGroup, messages::Welcome, prelude::KeyPackage};

use crate::{CryptoResult, MlsError, member::UserId};

#[cfg(not(debug_assertions))]
pub type ConversationId = ZeroKnowledgeUuid;
#[cfg(debug_assertions)]
pub type ConversationId = crate::identifiers::QualifiedUuid;

#[derive(Debug, Default)]
pub struct MlsConversationConfiguration {
    pub(crate) init_keys: Vec<KeyPackage>,
    pub(crate) admins: Vec<UserId>,
    // FIXME: No way to configure ciphersuites.
    // FIXME: Can maybe only check it against the supported ciphersuites in the group afterwards?
    // TODO: Maybe pull CiphersuiteName from OpenMLS
    pub(crate) _ciphersuite: (),
    // FIXME: openmls::group::config::UpdatePolicy is NOT configurable at the moment.
    // FIXME: None of the fields are available and there are no ways to build it/mutate it
    // TODO: Implement the key rotation manually instead.
    // TODO: Define if the rotation span is per X messages or per X epochs or even per X time interval
    pub(crate) _key_rotation_span: std::time::Duration,
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
#[allow(dead_code)]
pub struct MlsConversation {
    pub(crate) id: ConversationId,
    pub(crate) group: MlsGroup,
    pub(crate) admins: Vec<UserId>,
    configuration: MlsConversationConfiguration,
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
            openmls::group::GroupId::from_slice(id.to_string().as_bytes()),
            uuid::Uuid::new_v5(&uuid::Uuid::NAMESPACE_OID, b"test").as_bytes(),
        )
        .map_err(MlsError::from)?;

        let mut maybe_creation_message = None;
        if !config.init_keys.is_empty() {
            let (message, welcome) = group
                .add_members(backend, &config.init_keys)
                .map_err(MlsError::from)?;

            maybe_creation_message = Some(MlsConversationCreationMessage { message, welcome });
        }

        let conversation = Self {
            id,
            group,
            admins: config.admins.clone(),
            configuration: config,
        };

        Ok((conversation, maybe_creation_message))
    }

    pub fn id(&self) -> &ConversationId {
        &self.id
    }

    pub fn members(&self) -> std::collections::HashMap<UserId, openmls::credentials::Credential> {
        let mut ret = std::collections::HashMap::default();
        for c in self.group.members().unwrap() {
            let identity_str = std::str::from_utf8(c.identity()).unwrap();
            ret.insert(identity_str.parse().unwrap(), c.clone());
        }
        ret
    }

    pub fn can_user_act(&self, uuid: UserId) -> bool {
        self.admins.contains(&uuid)
    }

    pub fn decrypt_message<M: std::io::Read>(&mut self, message: &mut M, backend: &MlsCryptoProvider) -> CryptoResult<Vec<u8>> {
        use openmls::prelude::TlsDeserializeTrait as _;

        let raw_msg = openmls::framing::MlsCiphertext::tls_deserialize(message)
            .map_err(openmls::prelude::MlsCiphertextError::from)
            .map_err(MlsError::from)?;

        let msg_in = openmls::framing::MlsMessageIn::Ciphertext(Box::new(raw_msg));

        let parsed_message = self
            .group
            .parse_message(msg_in, backend)
            .map_err(MlsError::from)?;

        let message = self
            .group
            .process_unverified_message(parsed_message, None, backend)
            .map_err(MlsError::from)?;

        if let openmls::framing::ProcessedMessage::ApplicationMessage(app_msg) = message {
            let (buf, _sender) = app_msg.into_parts();
            Ok(buf)
        } else {
            unimplemented!("Types of messages other than ProcessedMessage::ApplicationMessage aren't supported just yet")
        }
    }

    pub fn encrypt_message<M: AsRef<[u8]>>(
        &mut self,
        message: M,
        backend: &MlsCryptoProvider,
    ) -> CryptoResult<Vec<u8>> {
        let message = self
            .group
            .create_message(backend, message.as_ref())
            .map_err(crate::MlsError::from)?;

        use openmls::prelude::TlsSerializeTrait as _;
        // TODO: Define serialization format? Probably won't be the TLS thingy?
        let buf = message
            .tls_serialize_detached()
            .map_err(openmls::prelude::MlsCiphertextError::from)
            .map_err(MlsError::from)?;

        Ok(buf)
    }
}

#[cfg(test)]
mod tests {
    use mls_crypto_provider::MlsCryptoProvider;
    use openmls::{ciphersuite::{ciphersuites::CiphersuiteName, Ciphersuite}, credentials::{CredentialBundle, CredentialType}, prelude::KeyPackageBundle, extensions::{KeyIdExtension, Extension}};
    use openmls_traits::{OpenMlsCryptoProvider, key_store::OpenMlsKeyStore};
    //use openmls_traits::{key_store::OpenMlsKeyStore, OpenMlsCryptoProvider};

    use super::{MlsConversation, MlsConversationConfiguration, ConversationId};
    use std::str::FromStr as _;

    #[inline(always)]
    fn init_keystore(identifier: &str) -> (MlsCryptoProvider, CredentialBundle, KeyPackageBundle) {
        let backend = MlsCryptoProvider::try_new_in_memory(
            "test1234"
        ).unwrap();

        // TODO: Add at least one key bundle
        let ciphersuite = Ciphersuite::new(CiphersuiteName::default()).unwrap();
        let raw_key_id = b"test_key";
        let key_id = uuid::Uuid::new_v5(&uuid::Uuid::NAMESPACE_OID, raw_key_id);

        let credentials = CredentialBundle::new(
            b"test_client".to_vec(),
            CredentialType::Basic,
            ciphersuite.signature_scheme(),
            &backend,
        )
        .unwrap();

        backend.key_store().store(
            &credentials.credential().signature_key(),
            &credentials,
        ).unwrap();

        let keypackage_bundle = KeyPackageBundle::new(
            &[ciphersuite.name()],
            &credentials,
            &backend,
            vec![Extension::KeyPackageId(KeyIdExtension::new(
                key_id.as_bytes(),
            ))],
        )
        .unwrap();

        keypackage_bundle.key_package().verify(&backend).unwrap();

        backend.key_store().store(
            &keypackage_bundle.key_package().hash(&backend).unwrap(),
            &keypackage_bundle
        ).unwrap();

        (backend, credentials, keypackage_bundle)
    }

    fn teardown_keystore(identifier: &str) {
        std::fs::remove_file(format!("./{}.db", identifier)).unwrap();
    }

    #[test]
    fn can_create_conversation() {
        let (
            mut backend,
            credentials,
            keypackage_bundle,
        ) = init_keystore("create_conversation");

        let conversation_id = ConversationId::from_str(
            "85764bcc-4fa1-451f-9e1a-c190a62a8de1@test.wire.com"
        ).unwrap();
        let (a, b) = MlsConversation::create(
            conversation_id.clone(),
            MlsConversationConfiguration {
                init_keys: vec![keypackage_bundle.key_package().clone()],
                admins: vec![],
                ..Default::default()
            },
            &mut backend
        ).unwrap();
        assert!(b.is_none());
        assert_eq!(a.id, conversation_id);
        assert_eq!(a.group.group_id().as_slice(), conversation_id.to_string().as_bytes());

        assert!(a.members().is_empty());

        teardown_keystore("create_conversation");
    }
}
