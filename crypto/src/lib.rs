mod error;
pub use self::error::*;

mod client;
mod conversation;
pub mod identifiers;
mod member;

pub mod prelude {
    pub use crate::client::*;
    pub use crate::conversation::*;
    pub use crate::error::*;
    pub use crate::identifiers;
    pub use crate::member::*;
    pub use crate::MlsCentral;
}

use client::Client;
use conversation::{ConversationId, MlsConversation, MlsConversationConfiguration, MlsConversationCreationMessage};
use mls_crypto_provider::MlsCryptoProvider;
use openmls::messages::Welcome;
use std::collections::HashMap;

#[derive(Debug)]
pub struct MlsCentral {
    mls_client: Option<Client>,
    mls_backend: MlsCryptoProvider,
    mls_groups: parking_lot::RwLock<HashMap<ConversationId, MlsConversation>>,
    welcome_callback: Option<fn(Welcome)>,
}

impl MlsCentral {
    /// Tries to initialize the MLS Central object.
    /// Takes a store path (i.e. Disk location of the embedded database, should be consistent between messaging sessions)
    /// And a root identity key (i.e. enclaved encryption key for this device)
    pub fn try_new<S: AsRef<str>>(store_path: S, identity_key: S) -> crate::error::CryptoResult<Self> {
        let mls_backend = mls_crypto_provider::MlsCryptoProvider::try_new(store_path, identity_key)?;

        Ok(Self {
            mls_backend,
            mls_client: None,
            mls_groups: HashMap::new().into(),
            welcome_callback: None,
        })
    }

    /// Callback for the welcome messages. The passed message will be passed along to the MLS DS
    pub fn on_welcome(&mut self, callback: fn(Welcome)) {
        self.welcome_callback = Some(callback);
    }

    /// Create a new empty conversation
    pub fn new_conversation(
        &mut self,
        id: ConversationId,
        config: MlsConversationConfiguration,
    ) -> crate::error::CryptoResult<Option<MlsConversationCreationMessage>> {
        let (conversation, messages) = MlsConversation::create(id.clone(), config, &self.mls_backend)?;
        self.mls_groups.write().insert(id, conversation);
        Ok(messages)
    }

    // pub fn add_member_to_conversation(
    //     &self,
    //     id: ConversationId,

    // )

    /// Encrypts a raw payload then serializes it to the TLS wire format
    pub fn encrypt_message<M: AsRef<[u8]>>(&self, conversation: ConversationId, message: M) -> CryptoResult<Vec<u8>> {
        let groups = self.mls_groups.read();
        let conversation = groups
            .get(&conversation)
            .ok_or(CryptoError::ConversationNotFound(conversation))?;

        conversation.encrypt_message(message, &self.mls_backend)
    }

    /// Deserializes a TLS-serialized message, then deciphers it
    /// Warning: This method only supports MLS Application Messages as of 0.0.1
    pub fn decrypt_message<M: AsRef<[u8]>>(
        &self,
        conversation_id: ConversationId,
        message: M,
    ) -> CryptoResult<Vec<u8>> {
        let groups = self.mls_groups.read();
        let conversation = groups
            .get(&conversation_id)
            .ok_or(CryptoError::ConversationNotFound(conversation_id))?;

        conversation.decrypt_message(message.as_ref(), &self.mls_backend)
    }
}

pub fn init() {}
