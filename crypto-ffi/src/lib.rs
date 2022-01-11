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

#[derive(Debug)]
pub struct CoreCrypto(std::sync::RwLock<MlsCentral>);

#[allow(dead_code, unused_variables)]
impl CoreCrypto {
    pub fn new(path: &str, key: &str) -> CryptoResult<Self> {
        let central = MlsCentral::try_new(path, key)?;
        Ok(CoreCrypto(std::sync::RwLock::new(central)))
    }

    pub fn create_conversation(
        &self,
        conversation_id: ConversationId,
        config: MlsConversationConfiguration,
    ) -> CryptoResult<Option<ConversationCreationMessage>> {
        let ret = self.0.write().unwrap().new_conversation(conversation_id, config)?;
        Ok(ret.map(TryInto::try_into).transpose()?)
    }

    pub fn decrypt_message(&self, conversation_id: ConversationId, payload: &[u8]) -> CryptoResult<Vec<u8>> {
        self.0.read().unwrap().decrypt_message(conversation_id, payload)
    }

    pub fn encrypt_message(&self, conversation_id: ConversationId, message: &[u8]) -> CryptoResult<Vec<u8>> {
        self.0.read().unwrap().encrypt_message(conversation_id, message)
    }
}

#[inline(always)]
pub fn init_with_path_and_key(path: &str, key: &str) -> CryptoResult<std::sync::Arc<CoreCrypto>> {
    Ok(std::sync::Arc::new(CoreCrypto::new(path, key)?))
}
