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
mod external_proposal;
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
    pub use openmls::prelude::GroupEpoch;
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
    #[non_exhaustive]
    pub struct MlsCentralConfiguration<'a> {
        pub store_path: &'a str,
        pub identity_key: &'a str,
        pub client_id: &'a str,
    }

    impl<'a> MlsCentralConfiguration<'a> {
        pub fn try_new(store_path: &'a str, identity_key: &'a str, client_id: &'a str) -> CryptoResult<Self> {
            // TODO: probably more complex rules to enforce
            if store_path.trim().is_empty() {
                return Err(CryptoError::MalformedIdentifier(store_path.to_string()));
            }
            // TODO: probably more complex rules to enforce
            if identity_key.trim().is_empty() {
                return Err(CryptoError::MalformedIdentifier(identity_key.to_string()));
            }
            // TODO: probably more complex rules to enforce
            if client_id.trim().is_empty() {
                return Err(CryptoError::MalformedIdentifier(client_id.to_string()));
            }
            Ok(Self {
                store_path,
                identity_key,
                client_id,
            })
        }

        #[cfg(test)]
        #[allow(dead_code)]
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
    mls_client: Client,
    mls_backend: MlsCryptoProvider,
    mls_groups: HashMap<ConversationId, MlsConversation>,
    callbacks: Option<Box<dyn CoreCryptoCallbacks + 'static>>,
}

impl MlsCentral {
    /// Tries to initialize the MLS Central object.
    /// Takes a store path (i.e. Disk location of the embedded database, should be consistent between messaging sessions)
    /// And a root identity key (i.e. enclaved encryption key for this device)
    pub fn try_new(configuration: MlsCentralConfiguration) -> CryptoResult<Self> {
        // Init backend (crypto + rand + keystore)
        let mls_backend = MlsCryptoProvider::try_new(&configuration.store_path, &configuration.identity_key)?;
        // Init client identity (load or create)
        let mls_client = Client::init(configuration.client_id.as_bytes().into(), &mls_backend)?;
        // Restore persisted groups if there are any
        let mls_groups = Self::restore_groups(&mls_backend)?;

        Ok(Self {
            mls_backend,
            mls_client,
            mls_groups,
            callbacks: None,
        })
    }

    pub fn try_new_in_memory(configuration: MlsCentralConfiguration) -> crate::error::CryptoResult<Self> {
        let mls_backend = MlsCryptoProvider::try_new_in_memory(&configuration.store_path)?;
        let mls_client = Client::init(configuration.client_id.as_bytes().into(), &mls_backend)?;
        let mls_groups = Self::restore_groups(&mls_backend)?;

        Ok(Self {
            mls_backend,
            mls_client,
            mls_groups,
            callbacks: None,
        })
    }

    fn restore_groups(
        backend: &MlsCryptoProvider,
    ) -> crate::error::CryptoResult<HashMap<ConversationId, MlsConversation>> {
        use core_crypto_keystore::CryptoKeystoreMls as _;
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
    pub fn callbacks(&mut self, callbacks: Box<dyn CoreCryptoCallbacks>) -> CryptoResult<()> {
        self.callbacks = Some(callbacks);
        Ok(())
    }

    /// Returns the client's public key as a buffer
    pub fn client_public_key(&self) -> CryptoResult<Vec<u8>> {
        Ok(self.mls_client.public_key().into())
    }

    /// Returns the client's id as a buffer
    pub fn client_id(&self) -> CryptoResult<Vec<u8>> {
        Ok(self.mls_client.id().clone().into())
    }

    pub fn client_keypackages(&self, amount_requested: usize) -> CryptoResult<Vec<KeyPackageBundle>> {
        self.mls_client
            .request_keying_material(amount_requested, &self.mls_backend)
    }

    /// Create a new empty conversation
    pub fn new_conversation(&mut self, id: ConversationId, config: MlsConversationConfiguration) -> CryptoResult<()> {
        let conversation = MlsConversation::create(id.clone(), &mut self.mls_client, config, &self.mls_backend)?;

        self.mls_groups.insert(id, conversation);

        Ok(())
    }

    /// Checks if a given conversation id exists locally
    pub fn conversation_exists(&self, id: &ConversationId) -> bool {
        self.mls_groups
            .keys()
            .find_map(|group_id| if group_id == id { Some(true) } else { None })
            .unwrap_or_default()
    }

    /// Create a conversation from a received MLS Welcome message
    pub fn process_welcome_message(
        &mut self,
        welcome: Welcome,
        configuration: MlsConversationConfiguration,
    ) -> CryptoResult<ConversationId> {
        let conversation = MlsConversation::from_welcome_message(welcome, configuration, &self.mls_backend)?;
        let conversation_id = conversation.id().clone();
        self.mls_groups.insert(conversation_id.clone(), conversation);

        Ok(conversation_id)
    }

    /// Create a conversation from a recieved MLS Welcome message
    pub fn process_raw_welcome_message(&mut self, welcome: Vec<u8>) -> crate::error::CryptoResult<ConversationId> {
        let configuration = MlsConversationConfiguration::default();
        let mut cursor = std::io::Cursor::new(welcome);
        let welcome = Welcome::tls_deserialize(&mut cursor).map_err(MlsError::from)?;
        self.process_welcome_message(welcome, configuration)
    }

    pub fn add_members_to_conversation(
        &mut self,
        id: &ConversationId,
        members: &mut [ConversationMember],
    ) -> CryptoResult<Option<MlsConversationCreationMessage>> {
        if let Some(callbacks) = self.callbacks.as_ref() {
            if !callbacks.authorize(id.clone(), self.mls_client.id().to_string()) {
                return Err(CryptoError::Unauthorized);
            }
        }

        if let Some(group) = self.mls_groups.get_mut(id) {
            Ok(Some(group.add_members(members, &self.mls_backend)?))
        } else {
            Ok(None)
        }
    }

    pub fn remove_members_from_conversation(
        &mut self,
        id: &ConversationId,
        clients: &[ClientId],
    ) -> CryptoResult<Option<MlsMessageOut>> {
        if let Some(callbacks) = self.callbacks.as_ref() {
            if !callbacks.authorize(id.clone(), self.mls_client.id().to_string()) {
                return Err(CryptoError::Unauthorized);
            }
        }

        if let Some(group) = self.mls_groups.get_mut(id) {
            Ok(Some(group.remove_members(clients, &self.mls_backend)?))
        } else {
            Ok(None)
        }
    }

    /// Leaves a conversation with all the clients of the current user
    pub fn leave_conversation(
        &mut self,
        conversation: ConversationId,
        // The user's other clients. This can be an empty array
        other_clients: &[ClientId],
    ) -> CryptoResult<MlsConversationLeaveMessage> {
        if let Some(mut group) = self.mls_groups.remove(&conversation) {
            Ok(group.leave(other_clients, &self.mls_backend)?)
        } else {
            Err(CryptoError::ConversationNotFound(conversation))
        }
    }

    /// Encrypts a raw payload then serializes it to the TLS wire format
    pub fn encrypt_message(
        &mut self,
        conversation: ConversationId,
        message: impl AsRef<[u8]>,
    ) -> CryptoResult<Vec<u8>> {
        let conversation = self
            .mls_groups
            .get_mut(&conversation)
            .ok_or(CryptoError::ConversationNotFound(conversation))?;

        conversation.encrypt_message(message, &self.mls_backend)
    }

    /// Deserializes a TLS-serialized message, then deciphers it
    /// This method will return None for the message in case the provided payload is
    /// a system message, such as Proposals and Commits
    pub fn decrypt_message(
        &mut self,
        conversation_id: ConversationId,
        message: impl AsRef<[u8]>,
    ) -> CryptoResult<Option<Vec<u8>>> {
        let conversation = self
            .mls_groups
            .get_mut(&conversation_id)
            .ok_or(CryptoError::ConversationNotFound(conversation_id))?;

        conversation.decrypt_message(message.as_ref(), &self.mls_backend)
    }

    /// Exports a TLS-serialized view of the current group state corresponding to the provided conversation ID.
    pub fn export_public_group_state(&self, conversation_id: &ConversationId) -> CryptoResult<Vec<u8>> {
        let conversation = self
            .mls_groups
            .get(conversation_id)
            .ok_or_else(|| CryptoError::ConversationNotFound(conversation_id.clone()))?;

        let state = conversation
            .group
            .export_public_group_state(&self.mls_backend)
            .map_err(MlsError::from)?;

        Ok(state.tls_serialize_detached().map_err(MlsError::from)?)
    }

    /// Destroys everything we have, in-memory and on disk.
    pub fn wipe(self) {
        self.mls_backend.destroy_and_reset();
    }

    /// Self updates the KeyPackage and automatically commits. Pending proposals will be commited
    pub fn update_keying_material(
        &mut self,
        conversation_id: ConversationId,
    ) -> CryptoResult<(MlsMessageOut, Option<Welcome>)> {
        let conversation = self
            .mls_groups
            .get_mut(&conversation_id)
            .ok_or(CryptoError::ConversationNotFound(conversation_id))?;

        conversation.update_keying_material(&self.mls_backend)
    }
}

#[cfg(test)]
pub mod test_utils {
    use crate::{config::MlsCentralConfiguration, MlsCentral};

    #[cfg(target_family = "wasm")]
    pub fn run_test(test: impl FnOnce(String) -> ()) {
        use rand::distributions::{Alphanumeric, DistString};
        let filename = Alphanumeric.sample_string(&mut rand::thread_rng(), 16);
        let filename = format!("{filename}.idb");
        test(filename);
    }

    #[cfg(not(target_family = "wasm"))]
    pub fn run_test(test: impl FnOnce(String) -> ()) {
        let tmp_dir = tempfile::tempdir().unwrap();
        let tmp_dir_argument = crate::MlsCentralConfiguration::tmp_store_path(&tmp_dir);
        test(tmp_dir_argument);
        tmp_dir.close().unwrap();
    }

    pub fn run_test_with_central(test: impl FnOnce(MlsCentral) -> ()) {
        run_test(move |path| {
            let configuration = MlsCentralConfiguration::try_new(&path, "test", "alice").unwrap();
            let central = MlsCentral::try_new(configuration).unwrap();
            test(central);
        })
    }

    pub fn run_test_with_client_id(client_id: &str, test: impl FnOnce(MlsCentral) -> ()) {
        run_test(move |path| {
            let configuration = MlsCentralConfiguration::try_new(&path, "test", client_id).unwrap();
            let central = MlsCentral::try_new(configuration).unwrap();
            test(central);
        })
    }
}

#[cfg(test)]
pub mod tests {
    use crate::test_utils::run_test;
    use crate::{prelude::MlsConversationConfiguration, CryptoError, MlsCentral, MlsCentralConfiguration};
    use wasm_bindgen_test::wasm_bindgen_test;
    wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_browser);

    pub mod invariants {
        use crate::test_utils::run_test;

        use super::*;

        #[test]
        #[wasm_bindgen_test]
        pub fn can_create_from_valid_configuration() {
            run_test(|tmp_dir_argument| {
                let configuration = MlsCentralConfiguration::try_new(&tmp_dir_argument, "test", "alice").unwrap();

                let central = MlsCentral::try_new(configuration);
                assert!(central.is_ok())
            })
        }

        #[test]
        #[wasm_bindgen_test]
        pub fn store_path_should_not_be_empty_nor_blank() {
            let configuration = MlsCentralConfiguration::try_new(" ", "test", "alice");
            match configuration {
                Err(CryptoError::MalformedIdentifier(value)) => assert_eq!(" ", value),
                _ => panic!(),
            }
        }

        #[test]
        #[wasm_bindgen_test]
        pub fn identity_key_should_not_be_empty_nor_blank() {
            run_test(|tmp_dir_argument| {
                let configuration = MlsCentralConfiguration::try_new(&tmp_dir_argument, " ", "alice");
                match configuration {
                    Err(CryptoError::MalformedIdentifier(value)) => assert_eq!(" ", value),
                    _ => panic!(),
                }
            })
        }

        #[test]
        #[wasm_bindgen_test]
        pub fn client_id_should_not_be_empty_nor_blank() {
            run_test(|tmp_dir_argument| {
                let configuration = MlsCentralConfiguration::try_new(&tmp_dir_argument, "test", " ");
                match configuration {
                    Err(CryptoError::MalformedIdentifier(value)) => assert_eq!(" ", value),
                    _ => panic!(),
                }
            })
        }
    }

    pub mod persistence {
        use super::*;
        use crate::test_utils::run_test;

        #[test]
        // FIXME: Enable it back once WASM keystore persistence is working
        // #[wasm_bindgen_test]
        pub fn can_persist_group_state() {
            run_test(|tmp_dir_argument| {
                let configuration = MlsCentralConfiguration::try_new(&tmp_dir_argument, "test", "potato").unwrap();

                let mut central = MlsCentral::try_new(configuration.clone()).unwrap();
                let conversation_configuration = MlsConversationConfiguration::default();
                let conversation_id = b"conversation".to_vec();
                let _ = central.new_conversation(conversation_id.clone(), conversation_configuration);

                drop(central);
                let mut central = MlsCentral::try_new(configuration).unwrap();
                let _ = central.encrypt_message(conversation_id, b"Test").unwrap();

                central.mls_backend.destroy_and_reset();
            })
        }
    }

    #[test]
    #[wasm_bindgen_test]
    pub fn can_fetch_client_public_key() {
        run_test(|tmp_dir_argument| {
            let configuration = MlsCentralConfiguration::try_new(&tmp_dir_argument, "test", "potato").unwrap();

            let central = MlsCentral::try_new(configuration.clone()).unwrap();
            assert!(central.client_public_key().is_ok());
        })
    }
}
