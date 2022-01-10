uniffi_macros::include_scaffolding!("CoreCrypto");

mod uniffi_support;

use core_crypto::prelude::*;
pub use core_crypto::CryptoError;

pub struct ConversationConfiguration {
    pub author: UserId,
    pub extra_members: Vec<UserId>,
    pub admins: Vec<UserId>,
    pub ciphersuite: Option<String>,
    pub key_rotation_span: Option<std::time::Duration>,
}

#[derive(Debug)]
pub struct ConversationCreationMessage {
    pub welcome: Vec<u8>,
    pub message: Vec<u8>,
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
        config: ConversationConfiguration,
    ) -> CryptoResult<Option<ConversationCreationMessage>> {
        unimplemented!()
        // let ret = self
        //     .0
        //     .write()
        //     .unwrap()
        //     .new_conversation(conversation_id, config.into())?;
        // Ok(ret.into())
    }

    pub fn decrypt_message(&self, conversation_id: ConversationId, message: &[u8]) -> CryptoResult<Vec<u8>> {
        unimplemented!()
    }

    pub fn encrypt_message(&self, conversation_id: ConversationId, message: &[u8]) -> CryptoResult<Vec<u8>> {
        unimplemented!()
    }
}

#[inline(always)]
pub fn init_with_path_and_key(path: &str, key: &str) -> CryptoResult<std::sync::Arc<CoreCrypto>> {
    Ok(std::sync::Arc::new(CoreCrypto::new(path, key)?))
}
