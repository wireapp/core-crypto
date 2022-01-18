uniffi_macros::include_scaffolding!("CoreCrypto");

mod uniffi_support;

use core_crypto::prelude::*;
pub use core_crypto::CryptoError;

#[derive(Debug)]
pub struct ConversationCreationMessage {
    pub welcome: Vec<u8>,
    pub message: Vec<u8>,
}

impl TryFrom<MlsConversationCreationMessage> for ConversationCreationMessage {
    type Error = CryptoError;

    fn try_from(msg: MlsConversationCreationMessage) -> Result<Self, Self::Error> {
        let (welcome, message) = msg.to_bytes_pairs()?;
        Ok(Self { welcome, message })
    }
}

#[derive(Debug, Clone)]
pub struct Invitee {
    pub id: Vec<u8>,
    pub kph: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct ConversationConfiguration {
    pub extra_members: Vec<Invitee>,
    pub admins: Vec<MemberId>,
    pub ciphersuite: Option<CiphersuiteName>,
    pub key_rotation_span: Option<std::time::Duration>,
}

#[derive(Debug)]
pub struct CoreCrypto(std::sync::RwLock<MlsCentral>);

#[allow(dead_code, unused_variables)]
impl CoreCrypto {
    pub fn new(path: &str, key: &str, client_id: &str) -> CryptoResult<Self> {
        let configuration = MlsCentralConfiguration::builder()
            .store_path(path.into())
            .identity_key(key.into())
            .client_id(client_id.into())
            .build()?;

        let central = MlsCentral::try_new(configuration)?;
        Ok(CoreCrypto(std::sync::RwLock::new(central)))
    }

    pub fn create_conversation(
        &self,
        conversation_id: ConversationId,
        config: ConversationConfiguration,
    ) -> CryptoResult<Option<ConversationCreationMessage>> {
        // FIXME: Fix the api on the core-crypto side and allow transforming FFI-side config to inner config
        // let ret = self.0.write().unwrap().new_conversation(conversation_id, config)?;
        // Ok(ret.map(TryInto::try_into).transpose()?)
        todo!()
    }

    pub fn decrypt_message(&self, conversation_id: ConversationId, payload: &[u8]) -> CryptoResult<Option<Vec<u8>>> {
        self.0.read().unwrap().decrypt_message(conversation_id, payload)
    }

    pub fn encrypt_message(&self, conversation_id: ConversationId, message: &[u8]) -> CryptoResult<Vec<u8>> {
        self.0.read().unwrap().encrypt_message(conversation_id, message)
    }
}

#[inline(always)]
pub fn init_with_path_and_key(path: &str, key: &str, client_id: &str) -> CryptoResult<std::sync::Arc<CoreCrypto>> {
    Ok(std::sync::Arc::new(CoreCrypto::new(path, key, client_id)?))
}
