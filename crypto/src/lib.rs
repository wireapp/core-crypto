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

pub use self::error::*;

#[cfg(test)]
pub use core_crypto_attributes::durable;

mod error;

/// MLS Abstraction
pub mod mls;

#[cfg(feature = "proteus")]
/// Proteus Abstraction
pub mod proteus;

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

    pub use crate::{
        error::*,
        mls::{
            client::*,
            config::MlsCentralConfiguration,
            conversation::{
                decrypt::MlsConversationDecryptMessage,
                handshake::{MlsCommitBundle, MlsConversationCreationMessage, MlsProposalBundle},
                public_group_state::{
                    MlsPublicGroupStateBundle, MlsPublicGroupStateEncryptionType, MlsRatchetTreeType,
                    PublicGroupStatePayload,
                },
                *,
            },
            credential::CertificateBundle,
            external_commit::MlsConversationInitBundle,
            member::*,
            proposal::{MlsProposal, MlsProposalRef},
            MlsCentral, MlsCiphersuite,
        },
        CoreCryptoCallbacks,
    };
}

/// This trait is used to provide callback mechanisms for the MlsCentral struct, for example for
/// operations like adding or removing memebers that can be authorized through a caller provided
/// authorization method.
pub trait CoreCryptoCallbacks: std::fmt::Debug + Send + Sync {
    /// Function responsible for authorizing an operation.
    /// Returns `true` if the operation is authorized.
    ///
    /// # Arguments
    /// * `conversation_id` - id of the group/conversation
    /// * `client_id` - id of the client to authorize
    fn authorize(&self, conversation_id: crate::prelude::ConversationId, client_id: crate::prelude::ClientId) -> bool;
    /// Function responsible for authorizing an operation for a given user.
    /// Use [external_client_id] & [existing_clients] to get all the 'client_id' belonging to the same user
    /// as [external_client_id]. Then, given those client ids, verify that at least one has the right role
    /// (is authorized) exactly like it's done in [authorize]
    /// Returns `true` if the operation is authorized.
    ///
    /// # Arguments
    /// * `conversation_id` - id of the group/conversation
    /// * `external_client_id` - id a client external to the MLS group
    /// * `existing_clients` - all the clients in the MLS group
    fn user_authorize(
        &self,
        conversation_id: crate::prelude::ConversationId,
        external_client_id: crate::prelude::ClientId,
        existing_clients: Vec<crate::prelude::ClientId>,
    ) -> bool;
    /// Validates if the given `client_id` belongs to one of the provided `existing_clients`
    /// This basically allows to defer the client ID parsing logic to the caller - because CoreCrypto is oblivious to such things
    ///
    /// # Arguments
    /// * `client_id` - client ID of the client referenced within the sent proposal
    /// * `existing_clients` - all the clients in the MLS group
    fn client_is_existing_group_user(
        &self,
        client_id: crate::prelude::ClientId,
        existing_clients: Vec<crate::prelude::ClientId>,
    ) -> bool;
}

#[derive(Debug)]
/// Wrapper superstruct for both [mls::MlsCentral] and [proteus::ProteusCentral]
/// As [std::ops::Deref] is implemented, this struct is automatically dereferred to [mls::MlsCentral] apart from `proteus_*` calls
pub struct CoreCrypto {
    mls: crate::mls::MlsCentral,
    #[cfg(feature = "proteus")]
    proteus: Option<crate::proteus::ProteusCentral>,
    #[cfg(not(feature = "proteus"))]
    #[allow(dead_code)]
    proteus: (),
}

impl From<crate::mls::MlsCentral> for CoreCrypto {
    fn from(mls: crate::mls::MlsCentral) -> Self {
        Self {
            mls,
            proteus: Default::default(),
        }
    }
}

impl std::ops::Deref for CoreCrypto {
    type Target = crate::mls::MlsCentral;

    fn deref(&self) -> &Self::Target {
        &self.mls
    }
}

impl std::ops::DerefMut for CoreCrypto {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.mls
    }
}

impl CoreCrypto {
    /// Allows to extract the MLS Client from the wrapper superstruct
    pub fn unwrap_mls(self) -> crate::mls::MlsCentral {
        self.mls
    }
}

#[cfg(feature = "proteus")]
impl CoreCrypto {
    /// Initializes the proteus client
    pub async fn proteus_init(&mut self) -> CryptoResult<()> {
        // ? Cannot inline the statement or the borrow checker gets really confused about the type of `keystore`
        let keystore = self.mls.mls_backend.borrow_keystore();
        let proteus_client = crate::proteus::ProteusCentral::try_new(keystore).await?;
        self.proteus = Some(proteus_client);

        Ok(())
    }

    /// Creates a proteus session from a prekey
    ///
    /// Warning: The Proteus client **MUST** be initialized with [CoreCrypto::proteus_init] first or an error will be returned
    pub async fn proteus_session_from_prekey(
        &mut self,
        session_id: &str,
        prekey: &[u8],
    ) -> CryptoResult<&mut crate::proteus::ProteusConversationSession> {
        if let Some(proteus) = &mut self.proteus {
            proteus.session_from_prekey(session_id, prekey).await
        } else {
            Err(CryptoError::ProteusNotInitialized)
        }
    }

    /// Creates a proteus session from a Proteus message envelope
    ///
    /// Warning: The Proteus client **MUST** be initialized with [CoreCrypto::proteus_init] first or an error will be returned
    pub async fn proteus_session_from_message(
        &mut self,
        session_id: &str,
        envelope: &[u8],
    ) -> CryptoResult<(&mut crate::proteus::ProteusConversationSession, Vec<u8>)> {
        if let Some(proteus) = &mut self.proteus {
            let keystore = self.mls.mls_backend.borrow_keystore_mut();
            proteus.session_from_message(keystore, session_id, envelope).await
        } else {
            Err(CryptoError::ProteusNotInitialized)
        }
    }

    /// Saves a proteus session in the keystore
    ///
    /// Warning: The Proteus client **MUST** be initialized with [CoreCrypto::proteus_init] first or an error will be returned
    pub async fn proteus_session_save(&self, session_id: &str) -> CryptoResult<()> {
        if let Some(proteus) = &self.proteus {
            let keystore = self.mls.mls_backend.borrow_keystore();
            proteus.session_save(keystore, session_id).await?;
            Ok(())
        } else {
            Err(CryptoError::ProteusNotInitialized)
        }
    }

    /// Deletes a proteus session from the keystore
    ///
    /// Warning: The Proteus client **MUST** be initialized with [CoreCrypto::proteus_init] first or an error will be returned
    pub async fn proteus_session_delete(&mut self, session_id: &str) -> CryptoResult<()> {
        if let Some(proteus) = &mut self.proteus {
            let keystore = self.mls.mls_backend.borrow_keystore();
            proteus.session_delete(keystore, session_id).await?;
            Ok(())
        } else {
            Err(CryptoError::ProteusNotInitialized)
        }
    }

    /// Proteus session accessor
    ///
    /// Warning: The Proteus client **MUST** be initialized with [CoreCrypto::proteus_init] first or an error will be returned
    pub fn proteus_session(
        &mut self,
        session_id: &str,
    ) -> CryptoResult<Option<&mut crate::proteus::ProteusConversationSession>> {
        if let Some(proteus) = &mut self.proteus {
            Ok(proteus.session(session_id))
        } else {
            Err(CryptoError::ProteusNotInitialized)
        }
    }

    /// Decrypts a proteus message envelope
    ///
    /// Warning: The Proteus client **MUST** be initialized with [CoreCrypto::proteus_init] first or an error will be returned
    pub async fn proteus_decrypt(&mut self, session_id: &str, ciphertext: &[u8]) -> CryptoResult<Vec<u8>> {
        if let Some(proteus) = &mut self.proteus {
            let keystore = self.mls.mls_backend.borrow_keystore_mut();
            proteus.decrypt(keystore, session_id, ciphertext).await
        } else {
            Err(CryptoError::ProteusNotInitialized)
        }
    }

    /// Encrypts proteus message for a given session ID
    ///
    /// Warning: The Proteus client **MUST** be initialized with [CoreCrypto::proteus_init] first or an error will be returned
    pub fn proteus_encrypt(&mut self, session_id: &str, plaintext: &[u8]) -> CryptoResult<Vec<u8>> {
        if let Some(proteus) = &mut self.proteus {
            proteus.encrypt(session_id, plaintext)
        } else {
            Err(CryptoError::ProteusNotInitialized)
        }
    }

    /// Encrypts a proteus message for several sessions ID. This is more efficient than other methods as the calls are batched.
    /// This also reduces the rountrips when crossing over the FFI
    ///
    /// Warning: The Proteus client **MUST** be initialized with [CoreCrypto::proteus_init] first or an error will be returned
    pub fn proteus_encrypt_batched(
        &mut self,
        sessions: &[impl AsRef<str>],
        plaintext: &[u8],
    ) -> CryptoResult<std::collections::HashMap<String, Vec<u8>>> {
        if let Some(proteus) = &mut self.proteus {
            proteus.encrypt_batched(sessions, plaintext)
        } else {
            Err(CryptoError::ProteusNotInitialized)
        }
    }

    /// Creates a new Proteus prekey and returns the CBOR-serialized version of the prekey bundle
    ///
    /// Warning: The Proteus client **MUST** be initialized with [CoreCrypto::proteus_init] first or an error will be returned
    pub async fn proteus_new_prekey(&self, prekey_id: u16) -> CryptoResult<Vec<u8>> {
        if let Some(proteus) = &self.proteus {
            let keystore = self.mls.mls_backend.borrow_keystore();
            Ok(proteus.new_prekey(prekey_id, keystore).await?)
        } else {
            Err(CryptoError::ProteusNotInitialized)
        }
    }

    /// Returns the proteus identity keypair
    ///
    /// Warning: The Proteus client **MUST** be initialized with [CoreCrypto::proteus_init] first or an error will be returned
    pub fn proteus_identity(&self) -> CryptoResult<&::proteus_wasm::keys::IdentityKeyPair> {
        if let Some(proteus) = &self.proteus {
            Ok(proteus.identity())
        } else {
            Err(CryptoError::ProteusNotInitialized)
        }
    }

    /// Returns the proteus identity's public key fingerprint
    ///
    /// Warning: The Proteus client **MUST** be initialized with [CoreCrypto::proteus_init] first or an error will be returned
    pub fn proteus_fingerprint(&self) -> CryptoResult<String> {
        if let Some(proteus) = &self.proteus {
            Ok(proteus.fingerprint())
        } else {
            Err(CryptoError::ProteusNotInitialized)
        }
    }

    /// Migrates an existing Cryptobox data store (whether a folder or an IndexedDB database) located at `path` to the keystore.
    ///
    ///The client can then be initialized with [CoreCrypto::proteus_init]
    pub async fn proteus_cryptobox_migrate(&self, path: &str) -> CryptoResult<()> {
        let keystore = self.mls.mls_backend.borrow_keystore();
        Ok(crate::proteus::ProteusCentral::cryptobox_migrate(keystore, path).await?)
    }
}
