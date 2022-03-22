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
mod proposal;

pub mod prelude {
    pub use crate::client::*;
    pub use crate::conversation::*;
    pub use crate::error::*;
    pub use crate::member::*;
    pub use crate::proposal::MlsProposal;
    pub use crate::CoreCryptoCallbacks;
    pub use crate::{config::MlsCentralConfiguration, MlsCentral, MlsCiphersuite};
    pub use openmls::prelude::Ciphersuite as CiphersuiteName;
    pub use openmls::prelude::KeyPackage;
    pub use tls_codec;
}

use client::{Client, ClientId};
use config::MlsCentralConfiguration;
use conversation::{
    ConversationId, MlsConversation, MlsConversationConfiguration, MlsConversationCreationMessage,
    MlsConversationLeaveMessage,
};
use member::ConversationMember;
use mls_crypto_provider::MlsCryptoProvider;
use openmls::{
    messages::Welcome,
    prelude::{Ciphersuite, KeyPackageBundle, MlsMessageOut},
};
use openmls_traits::OpenMlsCryptoProvider;
use std::collections::HashMap;
use tls_codec::{Deserialize, Serialize};

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
    type Target = Ciphersuite;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// Prevents direct instantiation of [MlsCentralConfiguration]
mod config {
    use super::*;

    #[derive(Debug, Clone)]
    pub struct MlsCentralConfiguration {
        pub store_path: String,
        pub identity_key: String,
        pub client_id: String,
        _private: (), // allow other fields access but prevent instantiation
    }

    impl MlsCentralConfiguration {
        pub fn try_new(store_path: String, identity_key: String, client_id: String) -> CryptoResult<Self> {
            // TODO: probably more complex rules to enforce
            if store_path.trim().is_empty() {
                return Err(CryptoError::MalformedIdentifier(store_path));
            }
            // TODO: probably more complex rules to enforce
            if identity_key.trim().is_empty() {
                return Err(CryptoError::MalformedIdentifier(identity_key));
            }
            // TODO: probably more complex rules to enforce
            if client_id.trim().is_empty() {
                return Err(CryptoError::MalformedIdentifier(client_id));
            }
            Ok(Self {
                store_path,
                identity_key,
                client_id,
                _private: (),
            })
        }

        #[cfg(test)]
        /// Creates temporary file to prevent test collisions which would happen with hardcoded file path
        pub(crate) fn tmp_store_path(tmp_dir: &tempfile::TempDir) -> String {
            let path = tmp_dir.path().join("store.edb");
            std::fs::File::create(&path).unwrap();
            path.to_str().unwrap().to_string()
        }
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
    pub fn try_new(configuration: MlsCentralConfiguration) -> CryptoResult<Self> {
        // Init backend (crypto + rand + keystore)
        let mls_backend = MlsCryptoProvider::try_new(&configuration.store_path, &configuration.identity_key)?;
        // Init client identity (load or create)
        let mls_client = Client::init(configuration.client_id.as_bytes().into(), &mls_backend)?.into();
        // Restore persisted groups if there are any
        let mls_groups = Self::restore_groups(&mls_backend)?.into();

        Ok(Self {
            mls_backend,
            mls_client,
            mls_groups,
            callbacks: None.into(),
        })
    }

    pub fn try_new_in_memory(configuration: MlsCentralConfiguration) -> crate::error::CryptoResult<Self> {
        let mls_backend = MlsCryptoProvider::try_new_in_memory(&configuration.store_path)?;
        let mls_client = Client::init(configuration.client_id.as_bytes().into(), &mls_backend)?.into();
        let mls_groups = Self::restore_groups(&mls_backend)?.into();

        Ok(Self {
            mls_backend,
            mls_client,
            mls_groups,
            callbacks: None.into(),
        })
    }

    fn restore_groups(
        backend: &MlsCryptoProvider,
    ) -> crate::error::CryptoResult<HashMap<ConversationId, MlsConversation>> {
        let states = backend.key_store().mls_groups_restore()?;
        if states.is_empty() {
            return Ok(HashMap::new());
        }

        let groups = states.into_iter().try_fold(
            HashMap::new(),
            |mut acc, (group_id, state)| -> CryptoResult<HashMap<ConversationId, MlsConversation>> {
                let conversation = MlsConversation::from_serialized_state(state)?;
                acc.insert(group_id, conversation);
                Ok(acc)
            },
        )?;
        Ok(groups)
    }

    /// Sets the consumer callbacks (i.e authorization callbacks for CoreCrypto to perform authorization calls when needed)
    pub fn callbacks(&self, callbacks: Box<dyn CoreCryptoCallbacks>) -> CryptoResult<()> {
        let mut cb_w = self.callbacks.write().map_err(|_| CryptoError::LockPoisonError)?;
        *cb_w = Some(callbacks);
        Ok(())
    }

    /// Returns the client's public key as a buffer
    pub fn client_public_key(&self) -> CryptoResult<Vec<u8>> {
        Ok(self
            .mls_client
            .read()
            .map_err(|_| CryptoError::LockPoisonError)?
            .public_key()
            .into())
    }

    /// Returns the client's id as a buffer
    pub fn client_id(&self) -> CryptoResult<Vec<u8>> {
        Ok(self
            .mls_client
            .read()
            .map_err(|_| CryptoError::LockPoisonError)?
            .id()
            .clone()
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
    ) -> CryptoResult<Option<MlsConversationCreationMessage>> {
        let mut client = self.mls_client.write().map_err(|_| CryptoError::LockPoisonError)?;
        let (conversation, messages) = MlsConversation::create(id.clone(), &mut client, config, &self.mls_backend)?;

        self.mls_groups
            .write()
            .map_err(|_| CryptoError::LockPoisonError)?
            .insert(id, conversation);

        Ok(messages)
    }

    /// Checks if a given conversation id exists locally
    pub fn conversation_exists(&self, id: &ConversationId) -> bool {
        self.mls_groups
            .read()
            .map(|groups| groups.contains_key(id))
            .unwrap_or_default()
    }

    /// Create a conversation from a received MLS Welcome message
    pub fn process_welcome_message(
        &self,
        welcome: Welcome,
        configuration: MlsConversationConfiguration,
    ) -> CryptoResult<ConversationId> {
        let conversation = MlsConversation::from_welcome_message(welcome, configuration, &self.mls_backend)?;
        let conversation_id = conversation.id().clone();
        self.mls_groups
            .write()
            .map_err(|_| CryptoError::LockPoisonError)?
            .insert(conversation_id.clone(), conversation);

        Ok(conversation_id)
    }

    /// Create a conversation from a recieved MLS Welcome message
    pub fn process_raw_welcome_message(&self, welcome: Vec<u8>) -> crate::error::CryptoResult<ConversationId> {
        let configuration = MlsConversationConfiguration::builder().build()?;
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
        clients: &[ClientId],
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
            Ok(Some(group.remove_members(clients, &self.mls_backend)?))
        } else {
            Ok(None)
        }
    }

    /// Leaves a conversation with all the clients of the current user
    pub fn leave_conversation(
        &self,
        conversation: ConversationId,
        // The user's other clients. This can be an empty array
        other_clients: &[ClientId],
    ) -> CryptoResult<MlsConversationLeaveMessage> {
        let mut groups = self.mls_groups.write().map_err(|_| CryptoError::LockPoisonError)?;
        if let Some(group) = groups.remove(&conversation) {
            Ok(group.leave(other_clients, &self.mls_backend)?)
        } else {
            Err(CryptoError::ConversationNotFound(conversation))
        }
    }

    /// Encrypts a raw payload then serializes it to the TLS wire format
    pub fn encrypt_message(&self, conversation: ConversationId, message: impl AsRef<[u8]>) -> CryptoResult<Vec<u8>> {
        let groups = self.mls_groups.read().map_err(|_| CryptoError::LockPoisonError)?;
        let conversation = groups
            .get(&conversation)
            .ok_or(CryptoError::ConversationNotFound(conversation))?;

        conversation.encrypt_message(message, &self.mls_backend)
    }

    /// Deserializes a TLS-serialized message, then deciphers it
    /// This method will return None for the message in case the provided payload is
    /// a system message, such as Proposals and Commits
    pub fn decrypt_message(
        &self,
        conversation_id: ConversationId,
        message: impl AsRef<[u8]>,
    ) -> CryptoResult<Option<Vec<u8>>> {
        let groups = self.mls_groups.read().map_err(|_| CryptoError::LockPoisonError)?;
        let conversation = groups
            .get(&conversation_id)
            .ok_or(CryptoError::ConversationNotFound(conversation_id))?;

        conversation.decrypt_message(message.as_ref(), &self.mls_backend)
    }

    /// Exports a TLS-serialized view of the current group state corresponding to the provided conversation ID.
    pub fn export_public_group_state(&self, conversation_id: &ConversationId) -> CryptoResult<Vec<u8>> {
        let groups = self.mls_groups.read().map_err(|_| CryptoError::LockPoisonError)?;
        let conversation = groups
            .get(conversation_id)
            .ok_or_else(|| CryptoError::ConversationNotFound(conversation_id.clone()))?;

        let state = conversation
            .group
            .read()
            .map_err(|_| CryptoError::LockPoisonError)?
            .export_public_group_state(&self.mls_backend)
            .map_err(MlsError::from)?;

        Ok(state.tls_serialize_detached().map_err(MlsError::from)?)
    }

    /// Destroys everything we have, in-memory and on disk.
    pub fn wipe(self) {
        self.mls_backend.destroy_and_reset();
    }
}

#[cfg(test)]
mod tests {
    use crate::{prelude::MlsConversationConfiguration, CryptoError, MlsCentral, MlsCentralConfiguration};

    mod invariants {
        use super::*;

        #[test]
        fn can_create_from_valid_configuration() {
            let tmp_dir = tempfile::tempdir().unwrap();
            let tmp_dir_argument = &tmp_dir;
            let configuration = MlsCentralConfiguration::try_new(
                MlsCentralConfiguration::tmp_store_path(&tmp_dir_argument),
                "test".to_string(),
                "alice".to_string(),
            )
            .unwrap();

            let central = MlsCentral::try_new(configuration);
            assert!(central.is_ok())
        }

        #[test]
        fn store_path_should_not_be_empty_nor_blank() {
            let configuration =
                MlsCentralConfiguration::try_new(" ".to_string(), "test".to_string(), "alice".to_string());
            match configuration {
                Err(CryptoError::MalformedIdentifier(value)) => assert_eq!(" ", value),
                _ => panic!(),
            }
        }

        #[test]
        fn identity_key_should_not_be_empty_nor_blank() {
            let tmp_dir = tempfile::tempdir().unwrap();
            let configuration = MlsCentralConfiguration::try_new(
                MlsCentralConfiguration::tmp_store_path(&tmp_dir),
                " ".to_string(),
                "alice".to_string(),
            );
            match configuration {
                Err(CryptoError::MalformedIdentifier(value)) => assert_eq!(" ", value),
                _ => panic!(),
            }
        }

        #[test]
        fn client_id_should_not_be_empty_nor_blank() {
            let tmp_dir = tempfile::tempdir().unwrap();
            let configuration = MlsCentralConfiguration::try_new(
                MlsCentralConfiguration::tmp_store_path(&tmp_dir),
                "test".to_string(),
                " ".to_string(),
            );
            match configuration {
                Err(CryptoError::MalformedIdentifier(value)) => assert_eq!(" ", value),
                _ => panic!(),
            }
        }
    }

    mod persistence {
        use super::*;

        #[test]
        fn can_persist_group_state() {
            let tmp_dir = tempfile::tempdir().unwrap();
            let configuration = MlsCentralConfiguration::try_new(
                MlsCentralConfiguration::tmp_store_path(&tmp_dir),
                "test".to_string(),
                "potato".to_string(),
            )
            .unwrap();

            let central = MlsCentral::try_new(configuration.clone()).unwrap();
            let conversation_configuration = MlsConversationConfiguration::default();
            let conversation_id = b"conversation".to_vec();
            let _ = central.new_conversation(conversation_id.clone(), conversation_configuration);

            drop(central);
            let central = MlsCentral::try_new(configuration).unwrap();
            let _ = central.encrypt_message(conversation_id, b"Test".to_vec()).unwrap();

            central.mls_backend.destroy_and_reset();
        }
    }
}
