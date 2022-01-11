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
        use core_crypto::prelude::openmls::prelude::TlsSerializeTrait as _;
        Ok(Self {
            welcome: msg
                .welcome
                .tls_serialize_detached()
                .map_err(core_crypto::prelude::openmls::prelude::WelcomeError::from)
                .map_err(MlsError::from)?,
            message: msg.message.to_bytes().map_err(MlsError::from)?,
        })
    }
}

#[derive(Debug)]
pub struct CoreCrypto(std::sync::Mutex<MlsCentral>);

#[allow(dead_code, unused_variables)]
impl CoreCrypto {
    pub fn new(path: &str, key: &str) -> CryptoResult<Self> {
        let central = MlsCentral::try_new(path, key)?;
        Ok(CoreCrypto(std::sync::Mutex::new(central)))
    }

    pub fn create_conversation(
        &self,
        conversation_id: ConversationId,
        config: MlsConversationConfiguration,
    ) -> CryptoResult<Option<ConversationCreationMessage>> {
        let ret = self.0.lock().unwrap().new_conversation(conversation_id, config)?;
        Ok(ret.map(TryInto::try_into).transpose()?)
    }

    pub fn decrypt_message(&self, conversation_id: ConversationId, message: Vec<u8>) -> CryptoResult<Vec<u8>> {
        let mut cursor = std::io::Cursor::new(message);
        self.0.lock().unwrap().decrypt_message(conversation_id, &mut cursor)
    }

    pub fn encrypt_message(&self, conversation_id: ConversationId, message: &[u8]) -> CryptoResult<Vec<u8>> {
        self.0.lock().unwrap().encrypt_message(conversation_id, message)
    }
}

#[inline(always)]
pub fn init_with_path_and_key(path: &str, key: &str) -> CryptoResult<std::sync::Arc<CoreCrypto>> {
    Ok(std::sync::Arc::new(CoreCrypto::new(path, key)?))
}
