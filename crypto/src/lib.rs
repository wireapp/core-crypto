// Wire
// Copyright (C) 2022 Wire Swiss GmbH

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with this program. If not, see http://www.gnu.org/licenses/.

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
    pub use crate::{MlsCentral, MlsCentralConfiguration};
    pub use openmls::ciphersuite::ciphersuites::CiphersuiteName;
}

use client::Client;
use conversation::{ConversationId, MlsConversation, MlsConversationConfiguration, MlsConversationCreationMessage};
use mls_crypto_provider::MlsCryptoProvider;
use openmls::messages::Welcome;
use std::collections::HashMap;

#[derive(Debug, Clone, derive_builder::Builder)]
pub struct MlsCentralConfiguration {
    pub(crate) store_path: String,
    pub(crate) identity_key: String,
    pub(crate) client_id: String,
}

impl MlsCentralConfiguration {
    pub fn builder() -> MlsCentralConfigurationBuilder {
        MlsCentralConfigurationBuilder::default()
    }
}

#[derive(Debug)]
pub struct MlsCentral {
    mls_client: std::sync::RwLock<Client>,
    mls_backend: MlsCryptoProvider,
    mls_groups: std::sync::RwLock<HashMap<ConversationId, MlsConversation>>,
    welcome_callback: Option<fn(Welcome)>,
}

impl MlsCentral {
    /// Tries to initialize the MLS Central object.
    /// Takes a store path (i.e. Disk location of the embedded database, should be consistent between messaging sessions)
    /// And a root identity key (i.e. enclaved encryption key for this device)
    pub fn try_new(configuration: MlsCentralConfiguration) -> crate::error::CryptoResult<Self> {
        let mls_backend =
            mls_crypto_provider::MlsCryptoProvider::try_new(&configuration.store_path, &configuration.identity_key)?;
        let mls_client = Client::init(configuration.client_id.parse()?, &mls_backend)?;

        Ok(Self {
            mls_backend,
            mls_client: mls_client.into(),
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
        &self,
        id: ConversationId,
        config: MlsConversationConfiguration,
    ) -> crate::error::CryptoResult<Option<MlsConversationCreationMessage>> {
        let mut client = self.mls_client.write().map_err(|_| CryptoError::LockPoisonError)?;
        let (conversation, messages) = MlsConversation::create(id.clone(), &mut client, config, &self.mls_backend)?;

        self.mls_groups
            .write()
            .map_err(|_| CryptoError::LockPoisonError)?
            .insert(id, conversation);

        Ok(messages)
    }

    // pub fn add_member_to_conversation(
    //     &self,
    //     id: ConversationId,

    // )

    /// Encrypts a raw payload then serializes it to the TLS wire format
    pub fn encrypt_message<M: AsRef<[u8]>>(&self, conversation: ConversationId, message: M) -> CryptoResult<Vec<u8>> {
        let groups = self.mls_groups.read().map_err(|_| CryptoError::LockPoisonError)?;
        let conversation = groups
            .get(&conversation)
            .ok_or(CryptoError::ConversationNotFound(conversation))?;

        conversation.encrypt_message(message, &self.mls_backend)
    }

    /// Deserializes a TLS-serialized message, then deciphers it
    /// This method will return None for the message in case the provided payload is
    /// a system message, such as Proposals and Commits
    pub fn decrypt_message<M: AsRef<[u8]>>(
        &self,
        conversation_id: ConversationId,
        message: M,
    ) -> CryptoResult<Option<Vec<u8>>> {
        let groups = self.mls_groups.read().map_err(|_| CryptoError::LockPoisonError)?;
        let conversation = groups
            .get(&conversation_id)
            .ok_or(CryptoError::ConversationNotFound(conversation_id))?;

        conversation.decrypt_message(message.as_ref(), &self.mls_backend)
    }
}
