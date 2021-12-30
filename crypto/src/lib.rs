mod error;
pub use self::error::*;

mod identifiers;
pub mod conversation;

pub mod prelude {
    pub use crate::error::*;
    pub use crate::conversation::*;
    pub use crate::MlsCentral;
}

use conversation::{MlsConversationConfiguration, ConversationId, MlsConversation, MlsConversationCreationMessage};
use mls_crypto_provider::MlsCryptoProvider;
use openmls::messages::Welcome;
use std::collections::HashMap;

#[derive(Debug)]
pub struct MlsCentral {
    mls_backend: MlsCryptoProvider,
    mls_groups: HashMap<ConversationId, MlsConversation>,
    welcome_callback: Option<fn(Welcome)>,
}

impl MlsCentral {
    /// Tries to initialize the MLS Central object.
    /// Takes a store path (i.e. Disk location of the embedded database, should be consistent between messaging sessions)
    /// And a root identity key (i.e. enclaved encryption key for this device)
    pub fn try_new<S: AsRef<str>>(
        store_path: S,
        identity_key: S,
    ) -> crate::error::CryptoResult<Self> {
        let mls_backend =
            mls_crypto_provider::MlsCryptoProvider::try_new(store_path, identity_key)?;

        Ok(Self {
            mls_backend,
            mls_groups: HashMap::new(),
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
        let (
            conversation,
            messages,
        ) = MlsConversation::create(id, config, &self.mls_backend)?;
        self.mls_groups.insert(id, conversation);
        Ok(messages)
    }

    // pub fn add_member_to_conversation(
    //     &self,
    //     id: ConversationId,

    // )

    /// Encrypts a raw payload then serializes it to the TLS wire format
    pub fn encrypt_message<M: AsRef<[u8]>>(
        &mut self,
        conversation: ConversationId,
        message: M,
    ) -> CryptoResult<Vec<u8>> {
        let conversation = self
            .mls_groups
            .get_mut(&conversation)
            .ok_or(CryptoError::ConversationNotFound(conversation))?;

        use openmls::prelude::{TlsSerializeTrait as _, TlsSizeTrait as _};

        let message = conversation.group
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

    /// Deserializes a TLS-serialized message, then deciphers it
    /// Warning: This method only supports MLS Application Messages as of 0.0.1
    pub fn decrypt_message<M: std::io::Read>(
        &mut self,
        conversation: ConversationId,
        message: &mut M,
    ) -> CryptoResult<Vec<u8>> {
        use openmls::prelude::TlsDeserializeTrait as _;

        let raw_msg = openmls::framing::MlsCiphertext::tls_deserialize(message)
            .map_err(openmls::prelude::MlsCiphertextError::from)
            .map_err(MlsError::from)?;

        let conversation = self
            .mls_groups
            .get_mut(&conversation)
            .ok_or(CryptoError::ConversationNotFound(conversation))?;

        let msg_in = openmls::framing::MlsMessageIn::Ciphertext(Box::new(raw_msg));

        let parsed_message = conversation.group
            .parse_message(msg_in, &self.mls_backend)
            .map_err(MlsError::from)?;

        let message = conversation.group
            .process_unverified_message(parsed_message, None, &self.mls_backend)
            .map_err(MlsError::from)?;

        if let openmls::framing::ProcessedMessage::ApplicationMessage(app_msg) = message {
            let (buf, _sender) = app_msg.into_parts();
            Ok(buf)
        } else {
            unimplemented!("Types of messages other than ProcessedMessage::ApplicationMessage aren't supported just yet")
        }
    }
}
