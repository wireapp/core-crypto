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
// pub mod identifiers;
mod member;

pub mod prelude {
    pub use crate::client::*;
    pub use crate::conversation::*;
    pub use crate::error::*;
    pub use crate::member::*;
    pub use crate::CoreCryptoCallbacks;
    pub use crate::{MlsCentral, MlsCentralConfiguration, MlsCiphersuite};
    pub use openmls::prelude::Ciphersuite as CiphersuiteName;
    pub use tls_codec;
}

use client::{Client, ClientId};
use conversation::{ConversationId, MlsConversation, MlsConversationConfiguration, MlsConversationCreationMessage};
use member::ConversationMember;
use mls_crypto_provider::MlsCryptoProvider;
use openmls::{
    messages::Welcome,
    prelude::{Ciphersuite, KeyPackageBundle, MlsMessageOut},
};
use std::collections::HashMap;
use tls_codec::Deserialize;

pub trait CoreCryptoCallbacks: std::fmt::Debug + Send + Sync {
    fn authorize(&self, conversation_id: ConversationId, client_id: String) -> bool;
}

#[derive(Debug, Clone)]
#[repr(transparent)]
/// Newtype for the OpenMLS Ciphersuite, so that we are able to provide a default value.
pub struct MlsCiphersuite(Ciphersuite);

impl Default for MlsCiphersuite {
    fn default() -> Self {
        Self(Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519)
    }
}

impl From<Ciphersuite> for MlsCiphersuite {
    fn from(value: Ciphersuite) -> Self {
        Self(value)
    }
}

impl std::ops::Deref for MlsCiphersuite {
    type Target = openmls::prelude::Ciphersuite;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

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
    callbacks: std::sync::RwLock<Option<Box<dyn CoreCryptoCallbacks + 'static>>>,
}

impl MlsCentral {
    /// Tries to initialize the MLS Central object.
    /// Takes a store path (i.e. Disk location of the embedded database, should be consistent between messaging sessions)
    /// And a root identity key (i.e. enclaved encryption key for this device)
    pub fn try_new(configuration: MlsCentralConfiguration) -> crate::error::CryptoResult<Self> {
        let mls_backend = MlsCryptoProvider::try_new(&configuration.store_path, &configuration.identity_key)?;
        let mls_client = Client::init(configuration.client_id.as_bytes().into(), &mls_backend)?;

        Ok(Self {
            mls_backend,
            mls_client: mls_client.into(),
            mls_groups: HashMap::new().into(),
            callbacks: None.into(),
        })
    }

    pub fn callbacks(&self, callbacks: Box<dyn CoreCryptoCallbacks>) -> CryptoResult<()> {
        let mut cb_w = self.callbacks.write().map_err(|_| CryptoError::LockPoisonError)?;
        *cb_w = Some(callbacks);
        Ok(())
    }

    pub fn client_public_key(&self) -> CryptoResult<Vec<u8>> {
        Ok(self
            .mls_client
            .read()
            .map_err(|_| CryptoError::LockPoisonError)?
            .public_key()
            .into())
    }

    pub fn client_keypackages(&self, amount_requested: usize) -> CryptoResult<Vec<KeyPackageBundle>> {
        self.mls_client
            .write()
            .map_err(|_| CryptoError::LockPoisonError)?
            .request_keying_material(amount_requested, &self.mls_backend)
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

    /// Create a conversation from a recieved MLS Welcome message
    pub fn process_welcome_message(
        &self,
        welcome: Welcome,
        configuration: MlsConversationConfiguration,
    ) -> crate::error::CryptoResult<ConversationId> {
        let conversation = MlsConversation::from_welcome_message(welcome, configuration, &self.mls_backend)?;
        let conversation_id = conversation.id().clone();
        self.mls_groups
            .write()
            .map_err(|_| CryptoError::LockPoisonError)?
            .insert(conversation_id.clone(), conversation);

        Ok(conversation_id)
    }

    pub fn process_raw_welcome_message(
        &self,
        welcome: Vec<u8>,
        configuration: MlsConversationConfiguration,
    ) -> crate::error::CryptoResult<ConversationId> {
        let mut cursor = std::io::Cursor::new(welcome);
        let welcome = Welcome::tls_deserialize(&mut cursor).map_err(MlsError::from)?;
        self.process_welcome_message(welcome, configuration)
    }

    pub fn add_members_to_conversation(
        &self,
        id: &ConversationId,
        members: &mut [ConversationMember],
    ) -> CryptoResult<Option<MlsConversationCreationMessage>> {
        if let Some(callbacks) = self
            .callbacks
            .read()
            .map_err(|_| CryptoError::LockPoisonError)?
            .as_ref()
        {
            if !callbacks.authorize(
                id.clone(),
                self.mls_client
                    .read()
                    .map_err(|_| CryptoError::LockPoisonError)?
                    .id()
                    .to_string(),
            ) {
                return Err(CryptoError::Unauthorized);
            }
        }

        if let Some(group) = self
            .mls_groups
            .write()
            .map_err(|_| CryptoError::LockPoisonError)?
            .get_mut(id)
        {
            Ok(Some(group.add_members(members, &self.mls_backend)?))
        } else {
            Ok(None)
        }
    }

    pub fn remove_members_from_conversation(
        &self,
        id: &ConversationId,
        members: &[ConversationMember],
    ) -> CryptoResult<Option<MlsMessageOut>> {
        if let Some(callbacks) = self
            .callbacks
            .read()
            .map_err(|_| CryptoError::LockPoisonError)?
            .as_ref()
        {
            if !callbacks.authorize(
                id.clone(),
                self.mls_client
                    .read()
                    .map_err(|_| CryptoError::LockPoisonError)?
                    .id()
                    .to_string(),
            ) {
                return Err(CryptoError::Unauthorized);
            }
        }

        if let Some(group) = self
            .mls_groups
            .write()
            .map_err(|_| CryptoError::LockPoisonError)?
            .get_mut(id)
        {
            Ok(Some(group.remove_members(members, &self.mls_backend)?))
        } else {
            Ok(None)
        }
    }

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

    pub fn wipe(self) {
        self.mls_backend.destroy_and_reset();
    }
}
