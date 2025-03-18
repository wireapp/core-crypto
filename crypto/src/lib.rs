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
#![cfg_attr(not(test), deny(missing_docs))]
#![allow(clippy::single_component_path_imports)]

use async_lock::Mutex;
#[cfg(test)]
pub use core_crypto_macros::{dispotent, durable, idempotent};
use std::sync::Arc;

pub use self::error::*;

#[cfg(test)]
#[macro_use]
pub mod test_utils;
// both imports above have to be defined at the beginning of the crate for rstest to work

mod error;

/// MLS Abstraction
pub mod mls;

/// re-export [rusty-jwt-tools](https://github.com/wireapp/rusty-jwt-tools) API
pub mod e2e_identity;

#[cfg(feature = "proteus")]
/// Proteus Abstraction
pub mod proteus;

pub mod context;
mod group_store;
mod obfuscate;

mod build_metadata;
use crate::prelude::MlsCommitBundle;
pub use build_metadata::{BUILD_METADATA, BuildMetadata};

/// Common imports that should be useful for most uses of the crate
pub mod prelude {
    pub use openmls::{
        group::{MlsGroup, MlsGroupConfig},
        prelude::{
            Ciphersuite as CiphersuiteName, Credential, GroupEpoch, KeyPackage, KeyPackageIn, KeyPackageRef,
            MlsMessageIn, Node, group_info::VerifiableGroupInfo,
        },
    };

    pub use mls_crypto_provider::{EntropySeed, MlsCryptoProvider, RawEntropySeed};

    pub use crate::{
        CoreCrypto, MlsTransport,
        e2e_identity::{
            E2eiEnrollment,
            conversation_state::E2eiConversationState,
            device_status::DeviceStatus,
            identity::{WireIdentity, X509Identity},
            types::{E2eiAcmeChallenge, E2eiAcmeDirectory, E2eiNewAcmeAuthz, E2eiNewAcmeOrder},
        },
        error::{CryptoboxMigrationError, Error, KeystoreError, LeafError, MlsError, ProteusError, RecursiveError},
        mls::{
            ciphersuite::MlsCiphersuite,
            client::Client,
            client::id::ClientId,
            client::identifier::ClientIdentifier,
            client::key_package::INITIAL_KEYING_MATERIAL_COUNT,
            client::*,
            config::MlsClientConfiguration,
            conversation::{
                ConversationId, MlsConversation,
                commit::{MlsCommitBundle, MlsConversationCreationMessage},
                config::{MlsConversationConfiguration, MlsCustomConfiguration, MlsWirePolicy},
                conversation_guard::decrypt::{MlsBufferedConversationDecryptMessage, MlsConversationDecryptMessage},
                group_info::{GroupInfoPayload, MlsGroupInfoBundle, MlsGroupInfoEncryptionType, MlsRatchetTreeType},
                proposal::MlsProposalBundle,
                welcome::WelcomeBundle,
            },
            credential::{typ::MlsCredentialType, x509::CertificateBundle},
            proposal::{MlsProposal, MlsProposalRef},
        },
        obfuscate::Obfuscated,
    };
}

/// Response from the delivery service
pub enum MlsTransportResponse {
    /// The message was accepted by the delivery service
    Success,
    /// A client should have consumed all incoming messages before re-trying.
    Retry,
    /// The message was rejected by the delivery service and there's no recovery.
    Abort {
        /// Why did the delivery service reject the message?
        reason: String,
    },
}

/// Client callbacks to allow communication with the delivery service.
/// There are two different endpoints, one for messages and one for commit bundles.
#[cfg_attr(target_family = "wasm", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_family = "wasm"), async_trait::async_trait)]
pub trait MlsTransport: std::fmt::Debug + Send + Sync {
    /// Send a commit bundle to the corresponding endpoint.
    async fn send_commit_bundle(&self, commit_bundle: MlsCommitBundle) -> Result<MlsTransportResponse>;
    /// Send a message to the corresponding endpoint.
    async fn send_message(&self, mls_message: Vec<u8>) -> Result<MlsTransportResponse>;
}

#[derive(Debug)]
/// Wrapper superstruct for both [mls::Client] and [proteus::ProteusCentral]
///
/// As [std::ops::Deref] is implemented, this struct is automatically dereferred to [mls::Client] apart from `proteus_*` calls
pub struct CoreCrypto {
    mls: mls::client::Client,
    #[cfg(feature = "proteus")]
    proteus: Arc<Mutex<Option<proteus::ProteusCentral>>>,
    #[cfg(not(feature = "proteus"))]
    #[allow(dead_code)]
    proteus: (),
}

impl From<mls::client::Client> for CoreCrypto {
    fn from(mls: mls::client::Client) -> Self {
        Self {
            mls,
            proteus: Default::default(),
        }
    }
}

impl std::ops::Deref for CoreCrypto {
    type Target = mls::client::Client;

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
    #[inline]
    pub fn take(self) -> mls::client::Client {
        self.mls
    }
}
