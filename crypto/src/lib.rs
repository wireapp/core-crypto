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

//! Core Crypto is a wrapper on top of OpenMLS aimed to provide an ergonomic API for usage in web
//! through Web Assembly and in mobile devices through FFI.
//!
//! The goal is provide a easier and less verbose API to create, manage and interact with MLS
//! groups.
#![doc = include_str!("../../README.md")]
#![deny(missing_docs)]
#![allow(clippy::single_component_path_imports)]

#[cfg(test)]
use rstest_reuse;

#[cfg(test)]
#[macro_use]
pub mod test_utils;
// both imports above have to be defined at the beginning of the crate for rstest to work

use std::collections::HashMap;

use openmls::{
    messages::Welcome,
    prelude::{Ciphersuite, KeyPackageBundle},
};
use openmls_traits::OpenMlsCryptoProvider;
use tls_codec::{Deserialize, Serialize};

use client::{Client, ClientId};
use config::MlsCentralConfiguration;
use conversation::{ConversationId, MlsConversation, MlsConversationConfiguration};
use credential::CertificateBundle;
use mls_crypto_provider::{MlsCryptoProvider, MlsCryptoProviderConfiguration};

pub use self::error::*;

#[cfg(test)]
pub use core_crypto_attributes::durable;

mod client;
mod conversation;
mod credential;
mod error;
mod external_commit;
mod external_proposal;
mod member;
mod proposal;

/// Common imports that should be useful for most uses of the crate
pub mod prelude {
    pub use openmls::group::{MlsGroup, MlsGroupConfig};
    pub use openmls::prelude::Ciphersuite as CiphersuiteName;
    pub use openmls::prelude::Credential;
    pub use openmls::prelude::GroupEpoch;
    pub use openmls::prelude::KeyPackage;
    pub use openmls::prelude::KeyPackageRef;
    pub use openmls::prelude::Node;
    pub use openmls::prelude::VerifiablePublicGroupState;
    pub use tls_codec;

    pub use mls_crypto_provider::{EntropySeed, RawEntropySeed};

    pub use crate::client::*;
    pub use crate::conversation::decrypt::MlsConversationDecryptMessage;
    pub use crate::conversation::handshake::{MlsCommitBundle, MlsConversationCreationMessage, MlsProposalBundle};
    pub use crate::conversation::public_group_state::PublicGroupStateBundle;
    pub use crate::conversation::*;
    pub use crate::credential::CertificateBundle;
    pub use crate::error::*;
    pub use crate::external_commit::MlsConversationInitBundle;
    pub use crate::member::*;
    pub use crate::proposal::MlsProposal;
    pub use crate::proposal::MlsProposalRef;
    pub use crate::CoreCryptoCallbacks;
    pub use crate::{config::MlsCentralConfiguration, MlsCentral, MlsCiphersuite};
}

/// This trait is used to provide callback mechanisms for the MlsCentral struct, for example for
/// operations like adding or removing memebers that can be authorized through a caller provided
/// authorization method.
pub trait CoreCryptoCallbacks: std::fmt::Debug + Send + Sync {
    /// Function responsible for authorizing an operation. Should return `true` if the operation is
    /// authorized
    ///
    /// # Arguments
    /// * `conversation_id` - id of the group/conversation
    /// * `client_id` - id of the client
    fn authorize(&self, conversation_id: Vec<u8>, client_id: Vec<u8>) -> bool;
    /// Validates if the given `client_id` belongs to one of the provided `other_clients`
    /// This basically allows to defer the client ID parsing logic to the caller - because CoreCrypto is oblivious to such things
    ///
    /// # Arguments
    /// * `client_id` - client ID of the client referenced within the sent proposal
    /// * `other_clients` - all the clients in the MLS group
    fn client_id_belongs_to_one_of(&self, client_id: Vec<u8>, other_clients: Vec<Vec<u8>>) -> bool;
}

#[derive(Debug, Clone, derive_more::Deref)]
#[repr(transparent)]
/// A wrapper for the OpenMLS Ciphersuite, so that we are able to provide a default value.
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

impl From<MlsCiphersuite> for Ciphersuite {
    fn from(ciphersuite: MlsCiphersuite) -> Self {
        ciphersuite.0
    }
}

// Prevents direct instantiation of [MlsCentralConfiguration]
mod config {
    use mls_crypto_provider::EntropySeed;

    use super::*;

    /// Configuration parameters for `MlsCentral`
    #[derive(Debug, Clone)]
    #[non_exhaustive]
    pub struct MlsCentralConfiguration {
        /// Location where the SQLite/IndexedDB database will be stored
        pub store_path: String,
        /// Identity key to be used to instanciate the [MlsCryptoProvider]
        pub identity_key: String,
        /// Identifier for the client to be used by [MlsCentral]
        pub client_id: String,
        /// Entropy pool seed for the internal PRNG
        pub external_entropy: Option<EntropySeed>,
    }

    impl MlsCentralConfiguration {
        /// Creates a new instance of the configuration.
        ///
        /// # Arguments
        /// * `store_path` - location where the SQLite/IndexedDB database will be stored
        /// * `identity_key` - identity key to be used to instanciante the [MlsCryptoProvider]
        /// * `client_id` - identifier for the client to be used by [MlsCentral]
        ///
        /// # Errors
        /// Any empty string parameter will result in a [CryptoError::MalformedIdentifier] error.
        ///
        /// # Examples
        ///
        /// This should fail:
        /// ```
        /// use core_crypto::{prelude::MlsCentralConfiguration, CryptoError};
        ///
        /// let result = MlsCentralConfiguration::try_new(String::new(), String::new(), String::new());
        /// assert!(matches!(result.unwrap_err(), CryptoError::MalformedIdentifier(_)));
        /// ```
        ///
        /// This should work:
        /// ```
        /// use core_crypto::{prelude::MlsCentralConfiguration, CryptoError};
        ///
        /// let result = MlsCentralConfiguration::try_new("/tmp/crypto".to_string(), "MY_IDENTITY_KEY".to_string(), "MY_CLIENT_ID".to_string());
        /// assert!(result.is_ok());
        /// ```
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
                external_entropy: None,
            })
        }

        /// Sets the entropy seed
        pub fn set_entropy(&mut self, entropy: EntropySeed) {
            self.external_entropy = Some(entropy);
        }

        #[cfg(test)]
        #[allow(dead_code)]
        /// Creates temporary file to prevent test collisions which would happen with hardcoded file path
        /// Intended to be used only in tests.
        pub(crate) fn tmp_store_path(tmp_dir: &tempfile::TempDir) -> String {
            let path = tmp_dir.path().join("store.edb");
            std::fs::File::create(&path).unwrap();
            path.to_str().unwrap().to_string()
        }
    }
}

/// The entry point for the Crypto-Core library. This struct provides all functionality to create
/// and manage groups, make proposals and commits.
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
    ///
    /// # Arguments
    /// * `configuration` - the configuration for the `MlsCentral`
    /// * `certificate_bundle` - an optional `CertificateBundle`. It will be used to generate the `CredentialBundle`. If `None`is passed, credentials of type a Basic will be created, otherwise a x509.
    ///
    /// # Errors
    /// Failures in the initialization of the KeyStore can cause errors, such as IO, the same kind
    /// of errors can happen when the groups are being restored from the KeyStore or even during
    /// the client initialization (to fetch the identity signature). Other than that, `MlsError`
    /// can be caused by group deserialization or during the initialization of the credentials:
    /// * for x509 Credentials if the cetificate chain length is lower than 2
    /// * for Basic Credentials if the signature key cannot be generated either by not supported
    /// scheme or the key generation fails
    pub async fn try_new(
        configuration: MlsCentralConfiguration,
        certificate_bundle: Option<CertificateBundle>,
    ) -> CryptoResult<Self> {
        // Init backend (crypto + rand + keystore)
        let mls_backend = MlsCryptoProvider::try_new_with_configuration(MlsCryptoProviderConfiguration {
            db_path: &configuration.store_path,
            identity_key: &configuration.identity_key,
            in_memory: false,
            entropy_seed: configuration.external_entropy,
        })
        .await?;

        // Init client identity (load or create)
        let mls_client = Client::init(
            configuration.client_id.as_bytes().into(),
            certificate_bundle,
            &mls_backend,
        )
        .await?;

        // Restore persisted groups if there are any
        let mls_groups = Self::restore_groups(&mls_backend).await?;

        Ok(Self {
            mls_backend,
            mls_client,
            mls_groups,
            callbacks: None,
        })
    }

    /// Same as the [crate::MlsCentral::try_new] but instead, it uses an in memory KeyStore. Although required, the `store_path` parameter from the `MlsCentralConfiguration` won't be used here.
    pub async fn try_new_in_memory(
        configuration: MlsCentralConfiguration,
        certificate_bundle: Option<CertificateBundle>,
    ) -> crate::error::CryptoResult<Self> {
        let mls_backend = MlsCryptoProvider::try_new_with_configuration(MlsCryptoProviderConfiguration {
            db_path: &configuration.store_path,
            identity_key: &configuration.identity_key,
            in_memory: true,
            entropy_seed: configuration.external_entropy,
        })
        .await?;
        let mls_client = Client::init(
            configuration.client_id.as_bytes().into(),
            certificate_bundle,
            &mls_backend,
        )
        .await?;
        let mls_groups = Self::restore_groups(&mls_backend).await?;

        Ok(Self {
            mls_backend,
            mls_client,
            mls_groups,
            callbacks: None,
        })
    }

    /// Restore existing groups from the KeyStore.
    async fn restore_groups(
        backend: &MlsCryptoProvider,
    ) -> crate::error::CryptoResult<HashMap<ConversationId, MlsConversation>> {
        use core_crypto_keystore::CryptoKeystoreMls as _;
        let states = backend.key_store().mls_groups_restore().await?;
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
    ///
    /// # Arguments
    /// * `callbacks` - a callback to be called to perform authorization
    pub fn callbacks(&mut self, callbacks: Box<dyn CoreCryptoCallbacks>) {
        self.callbacks = Some(callbacks);
    }

    /// Returns the client's public key as a buffer
    pub fn client_public_key(&self) -> Vec<u8> {
        self.mls_client.public_key().into()
    }

    /// Returns the client's id as a buffer
    pub fn client_id(&self) -> ClientId {
        self.mls_client.id().clone()
    }

    /// Returns `amount_requested` OpenMLS [`KeyPackageBundle`]s.
    /// Will always return the requested amount as it will generate the necessary (lacking) amount on-the-fly
    ///
    /// Note: Keypackage pruning is performed as a first step
    ///
    /// # Arguments
    /// * `amount_requested` - number of KeyPackages to request and fill the `KeyPackageBundle`
    ///
    /// # Return type
    /// A vector of `KeyPackageBundle`
    ///
    /// # Errors
    /// Errors can happen when accessing the KeyStore
    pub async fn client_keypackages(&self, amount_requested: usize) -> CryptoResult<Vec<KeyPackageBundle>> {
        self.mls_client
            .request_keying_material(amount_requested, &self.mls_backend)
            .await
    }

    /// Returns the count of valid, non-expired, unclaimed keypackages in store
    pub async fn client_valid_keypackages_count(&self) -> CryptoResult<usize> {
        self.mls_client.valid_keypackages_count(&self.mls_backend).await
    }

    /// Create a new empty conversation
    ///
    /// # Arguments
    /// * `id` - identifier of the group/conversation (must be unique otherwise the existing group
    /// will be overridden)
    /// * `config` - configuration of the group/conversation
    ///
    /// # Errors
    /// Errors can happen from the KeyStore or from OpenMls for ex if no [KeyPackageBundle] can
    /// be found in the KeyStore
    pub async fn new_conversation(
        &mut self,
        id: ConversationId,
        config: MlsConversationConfiguration,
    ) -> CryptoResult<()> {
        let conversation = MlsConversation::create(id.clone(), &mut self.mls_client, config, &self.mls_backend).await?;

        self.mls_groups.insert(id, conversation);

        Ok(())
    }

    /// Checks if a given conversation id exists locally
    pub fn conversation_exists(&self, id: &ConversationId) -> bool {
        self.mls_groups.contains_key(id)
    }

    /// Returns the epoch of a given conversation
    ///
    /// # Errors
    /// If the conversation can't be found
    pub fn conversation_epoch(&self, id: &ConversationId) -> CryptoResult<u64> {
        Ok(self
            .mls_groups
            .get(id)
            .ok_or_else(|| CryptoError::ConversationNotFound(id.to_owned()))?
            .group
            .epoch()
            .as_u64())
    }

    /// Create a conversation from a received MLS Welcome message
    ///
    /// # Arguments
    /// * `welcome` - a `Welcome` message received as a result of a commit adding new members to a group
    /// * `configuration` - configuration of the group/conversation
    ///
    /// # Return type
    /// This function will return the conversation/group id
    ///
    /// # Errors
    /// Errors can be originating from the KeyStore of from OpenMls:
    /// * if no [KeyPackageBundle] can be read from the KeyStore
    /// * if the message can't be decrypted
    pub async fn process_welcome_message(
        &mut self,
        welcome: Welcome,
        configuration: MlsConversationConfiguration,
    ) -> CryptoResult<ConversationId> {
        let conversation = MlsConversation::from_welcome_message(welcome, configuration, &self.mls_backend).await?;
        let conversation_id = conversation.id().clone();
        self.mls_groups.insert(conversation_id.clone(), conversation);

        Ok(conversation_id)
    }

    /// Create a conversation from a TLS serialized MLS Welcome message. The `MlsConversationConfiguration` used in this function will be the default implementation.
    ///
    /// # Arguments
    /// * `welcome` - a TLS serialized welcome message
    ///
    /// # Return type
    /// This function will return the conversation/group id
    ///
    /// # Errors
    /// see [MlsCentral::process_welcome_message]
    pub async fn process_raw_welcome_message(
        &mut self,
        welcome: Vec<u8>,
    ) -> crate::error::CryptoResult<ConversationId> {
        let configuration = MlsConversationConfiguration::default();
        let mut cursor = std::io::Cursor::new(welcome);
        let welcome = Welcome::tls_deserialize(&mut cursor).map_err(MlsError::from)?;
        self.process_welcome_message(welcome, configuration).await
    }

    /// Exports a TLS-serialized view of the current group state corresponding to the provided conversation ID.
    ///
    /// # Arguments
    /// * `conversation` - the group/conversation id
    /// * `message` - the encrypted message as a byte array
    ///
    /// # Return type
    /// A TLS serialized byte array of the `PublicGroupState`
    ///
    /// # Errors
    /// If the conversation can't be found, an error will be returned. Other errors are originating
    /// from OpenMls and serialization
    pub async fn export_public_group_state(&self, conversation_id: &ConversationId) -> CryptoResult<Vec<u8>> {
        let conversation = self.get_conversation(conversation_id)?;
        let state = conversation
            .group
            .export_public_group_state(&self.mls_backend)
            .await
            .map_err(MlsError::from)?;

        Ok(state.tls_serialize_detached().map_err(MlsError::from)?)
    }

    /// Closes the connection with the local KeyStore
    ///
    /// # Errors
    /// KeyStore errors, such as IO
    pub async fn close(self) -> CryptoResult<()> {
        self.mls_backend.close().await?;
        Ok(())
    }

    /// Destroys everything we have, in-memory and on disk.
    ///
    /// # Errors
    /// KeyStore errors, such as IO
    pub async fn wipe(self) -> CryptoResult<()> {
        self.mls_backend.destroy_and_reset().await?;
        Ok(())
    }

    /// Generates a random byte array of the specified size
    pub fn random_bytes(&self, len: usize) -> CryptoResult<Vec<u8>> {
        use openmls_traits::random::OpenMlsRand as _;
        Ok(self.mls_backend.rand().random_vec(len)?)
    }

    /// Returns a reference for the internal Crypto Provider
    pub fn provider(&self) -> &MlsCryptoProvider {
        &self.mls_backend
    }

    /// Returns a mutable reference for the internal Crypto Provider
    pub fn provider_mut(&mut self) -> &mut MlsCryptoProvider {
        &mut self.mls_backend
    }
}

#[cfg(test)]
pub mod tests {
    use wasm_bindgen_test::*;

    use crate::{
        credential::CredentialSupplier, prelude::MlsConversationConfiguration, test_utils::*, CryptoError, MlsCentral,
        MlsCentralConfiguration,
    };

    wasm_bindgen_test_configure!(run_in_browser);

    pub mod conversation_epoch {
        use super::*;

        #[apply(all_cipher_cred)]
        #[wasm_bindgen_test]
        pub async fn can_get_newly_created_conversation_epoch(
            credential: CredentialSupplier,
            cfg: MlsConversationConfiguration,
        ) {
            run_test_with_central(credential, move |[mut central]| {
                Box::pin(async move {
                    let id = conversation_id();
                    central.new_conversation(id.clone(), cfg).await.unwrap();
                    let epoch = central.conversation_epoch(&id).unwrap();
                    assert_eq!(epoch, 0);
                })
            })
            .await;
        }

        #[apply(all_cipher_cred)]
        #[wasm_bindgen_test]
        pub async fn can_get_conversation_epoch(credential: CredentialSupplier, cfg: MlsConversationConfiguration) {
            run_test_with_client_ids(
                credential,
                ["alice", "bob"],
                move |[mut alice_central, mut bob_central]| {
                    Box::pin(async move {
                        let id = conversation_id();
                        alice_central.new_conversation(id.clone(), cfg).await.unwrap();
                        alice_central.invite(&id, &mut bob_central).await.unwrap();
                        let epoch = alice_central.conversation_epoch(&id).unwrap();
                        assert_eq!(epoch, 1);
                    })
                },
            )
            .await;
        }

        #[apply(all_cipher_cred)]
        #[wasm_bindgen_test]
        pub async fn conversation_not_found(credential: CredentialSupplier, cfg: MlsConversationConfiguration) {
            run_test_with_central(credential, move |[central]| {
                Box::pin(async move {
                    let id = conversation_id();
                    let err = central.conversation_epoch(&id).unwrap_err();
                    assert!(matches!(err, CryptoError::ConversationNotFound(conv_id) if conv_id == id));
                })
            })
            .await;
        }
    }

    pub mod invariants {
        use super::*;

        #[apply(all_cipher_cred)]
        #[wasm_bindgen_test]
        pub async fn can_create_from_valid_configuration(
            credential: CredentialSupplier,
            cfg: MlsConversationConfiguration,
        ) {
            run_tests(move |[tmp_dir_argument]| {
                Box::pin(async move {
                    let configuration =
                        MlsCentralConfiguration::try_new(tmp_dir_argument, "test".to_string(), "alice".to_string())
                            .unwrap();

                    let central = MlsCentral::try_new(configuration, credential()).await;
                    assert!(central.is_ok())
                })
            })
            .await
        }

        #[test]
        #[wasm_bindgen_test]
        pub fn store_path_should_not_be_empty_nor_blank() {
            let configuration =
                MlsCentralConfiguration::try_new(" ".to_string(), "test".to_string(), "alice".to_string());
            match configuration {
                Err(CryptoError::MalformedIdentifier(value)) => assert_eq!(" ", value),
                _ => panic!(),
            }
        }

        #[cfg_attr(not(target_family = "wasm"), async_std::test)]
        #[wasm_bindgen_test]
        pub async fn identity_key_should_not_be_empty_nor_blank() {
            run_tests(|[tmp_dir_argument]| {
                Box::pin(async move {
                    let configuration =
                        MlsCentralConfiguration::try_new(tmp_dir_argument, " ".to_string(), "alice".to_string());
                    match configuration {
                        Err(CryptoError::MalformedIdentifier(value)) => assert_eq!(" ", value),
                        _ => panic!(),
                    }
                })
            })
            .await
        }

        #[cfg_attr(not(target_family = "wasm"), async_std::test)]
        #[wasm_bindgen_test]
        pub async fn client_id_should_not_be_empty_nor_blank() {
            run_tests(|[tmp_dir_argument]| {
                Box::pin(async move {
                    let configuration =
                        MlsCentralConfiguration::try_new(tmp_dir_argument, "test".to_string(), " ".to_string());
                    match configuration {
                        Err(CryptoError::MalformedIdentifier(value)) => assert_eq!(" ", value),
                        _ => panic!(),
                    }
                })
            })
            .await
        }
    }

    pub mod persistence {
        use super::*;

        #[apply(all_cipher_cred)]
        #[wasm_bindgen_test]
        pub async fn can_persist_group_state(credential: CredentialSupplier, cfg: MlsConversationConfiguration) {
            run_tests(move |[tmp_dir_argument]| {
                Box::pin(async move {
                    let configuration =
                        MlsCentralConfiguration::try_new(tmp_dir_argument, "test".to_string(), "potato".to_string())
                            .unwrap();

                    let mut central = MlsCentral::try_new(configuration.clone(), credential()).await.unwrap();
                    let conversation_configuration = cfg;
                    let id = conversation_id();
                    let _ = central.new_conversation(id.clone(), conversation_configuration).await;

                    central.close().await.unwrap();
                    let mut central = MlsCentral::try_new(configuration, credential()).await.unwrap();
                    let _ = central.encrypt_message(&id, b"Test").await.unwrap();

                    central.mls_backend.destroy_and_reset().await.unwrap();
                })
            })
            .await
        }
    }

    #[apply(all_cipher_cred)]
    #[wasm_bindgen_test]
    pub async fn can_fetch_client_public_key(credential: CredentialSupplier, cfg: MlsConversationConfiguration) {
        run_tests(move |[tmp_dir_argument]| {
            Box::pin(async move {
                let configuration =
                    MlsCentralConfiguration::try_new(tmp_dir_argument, "test".to_string(), "potato".to_string())
                        .unwrap();

                let result = MlsCentral::try_new(configuration.clone(), credential()).await;
                assert!(result.is_ok());
            })
        })
        .await
    }
}
