//! Core Crypto is a wrapper on top of OpenMLS aimed to provide an ergonomic API for usage in web
//! through Web Assembly and in mobile devices through FFI.
//!
//! The goal is provide a easier and less verbose API to create, manage and interact with MLS
//! groups.
#![doc = include_str!(env!("STRIPPED_README_PATH"))]
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

/// Proteus Abstraction
#[cfg(feature = "proteus")]
pub mod proteus;

mod ephemeral;
mod group_store;
mod obfuscate;
pub mod transaction_context;

mod build_metadata;
use crate::prelude::MlsCommitBundle;
pub use build_metadata::{BUILD_METADATA, BuildMetadata};

pub use core_crypto_keystore::DatabaseKey;

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
            device_status::DeviceStatus,
            identity::{WireIdentity, X509Identity},
            types::{E2eiAcmeChallenge, E2eiAcmeDirectory, E2eiNewAcmeAuthz, E2eiNewAcmeOrder},
        },
        ephemeral::HistorySecret,
        error::{CryptoboxMigrationError, Error, KeystoreError, LeafError, MlsError, ProteusError, RecursiveError},
        mls::{
            ciphersuite::MlsCiphersuite,
            config::MlsClientConfiguration,
            conversation::{
                ConversationId, MlsConversation,
                commit::MlsCommitBundle,
                config::{MlsConversationConfiguration, MlsCustomConfiguration, MlsWirePolicy},
                conversation_guard::decrypt::{MlsBufferedConversationDecryptMessage, MlsConversationDecryptMessage},
                group_info::{GroupInfoPayload, MlsGroupInfoBundle, MlsGroupInfoEncryptionType, MlsRatchetTreeType},
                proposal::MlsProposalBundle,
                welcome::WelcomeBundle,
            },
            credential::{typ::MlsCredentialType, x509::CertificateBundle},
            proposal::{MlsProposal, MlsProposalRef},
            session::Session,
            session::id::ClientId,
            session::identifier::ClientIdentifier,
            session::key_package::INITIAL_KEYING_MATERIAL_COUNT,
            session::*,
        },
        obfuscate::Obfuscated,
        transaction_context::e2e_identity::{E2eiDumpedPkiEnv, conversation_state::E2eiConversationState},
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

/// Wrapper superstruct for both [mls::session::Session] and [proteus::ProteusCentral]
///
/// As [std::ops::Deref] is implemented, this struct is automatically dereferred to [mls::session::Session] apart from `proteus_*` calls
///
/// This is cheap to clone as all internal members have `Arc` wrappers or are `Copy`.
#[derive(Debug, Clone)]
pub struct CoreCrypto {
    mls: mls::session::Session,
    #[cfg(feature = "proteus")]
    proteus: Arc<Mutex<Option<proteus::ProteusCentral>>>,
    #[cfg(not(feature = "proteus"))]
    #[allow(dead_code)]
    proteus: (),
}

impl From<mls::session::Session> for CoreCrypto {
    fn from(mls: mls::session::Session) -> Self {
        Self {
            mls,
            proteus: Default::default(),
        }
    }
}

impl std::ops::Deref for CoreCrypto {
    type Target = mls::session::Session;

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
    pub fn take(self) -> mls::session::Session {
        self.mls
    }
}
