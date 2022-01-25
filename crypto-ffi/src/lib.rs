#[cfg(feature = "uniffi")]
uniffi_macros::include_scaffolding!("CoreCrypto");

#[cfg(feature = "uniffi")]
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
    pub id: ClientId,
    pub kp: Vec<u8>,
}

impl TryInto<ConversationMember> for Invitee {
    type Error = CryptoError;

    fn try_into(self) -> Result<ConversationMember, Self::Error> {
        ConversationMember::new_raw(self.id, self.kp)
    }
}

#[derive(Debug, Clone)]
pub struct ConversationConfiguration {
    pub extra_members: Vec<Invitee>,
    pub admins: Vec<MemberId>,
    pub ciphersuite: Option<CiphersuiteName>,
    pub key_rotation_span: Option<std::time::Duration>,
}

#[derive(Debug)]
#[repr(transparent)]
pub struct CoreCrypto(MlsCentral);

#[allow(dead_code, unused_variables)]
impl CoreCrypto {
    pub fn new(path: &str, key: &str, client_id: &str) -> CryptoResult<Self> {
        let configuration = MlsCentralConfiguration::builder()
            .store_path(path.into())
            .identity_key(key.into())
            .client_id(client_id.into())
            .build()?;

        let central = MlsCentral::try_new(configuration)?;

        Ok(CoreCrypto(central))
    }

    pub fn create_conversation(
        &self,
        conversation_id: ConversationId,
        mut config: ConversationConfiguration,
    ) -> CryptoResult<Option<ConversationCreationMessage>> {
        let mut cfg = MlsConversationConfiguration::builder();
        let extra_members = config.extra_members.into_iter().try_fold(
            vec![],
            |mut acc, inv| -> CryptoResult<Vec<ConversationMember>> {
                acc.push(inv.try_into()?);
                Ok(acc)
            },
        )?;

        cfg.extra_members(extra_members);
        cfg.admins(config.admins);
        cfg.key_rotation_span(config.key_rotation_span);

        if let Some(ciphersuite) = config.ciphersuite.take() {
            cfg.ciphersuite(ciphersuite);
        }

        let ret = self.0.new_conversation(conversation_id, cfg.build()?)?;

        Ok(ret.map(TryInto::try_into).transpose()?)
    }

    pub fn decrypt_message(&self, conversation_id: ConversationId, payload: &[u8]) -> CryptoResult<Option<Vec<u8>>> {
        self.0.decrypt_message(conversation_id, payload)
    }

    pub fn encrypt_message(&self, conversation_id: ConversationId, message: &[u8]) -> CryptoResult<Vec<u8>> {
        self.0.encrypt_message(conversation_id, message)
    }
}

// #[cfg(not(wasm))]
#[no_mangle]
pub fn init_with_path_and_key(path: &str, key: &str, client_id: &str) -> CryptoResult<std::sync::Arc<CoreCrypto>> {
    Ok(std::sync::Arc::new(CoreCrypto::new(path, key, client_id)?))
}

const VERSION: &str = env!("CARGO_PKG_VERSION");

#[no_mangle]
pub extern "C" fn version() -> *const u8 {
    VERSION.as_ptr()
}
