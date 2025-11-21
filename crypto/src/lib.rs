//! Core Crypto is a wrapper on top of OpenMLS aimed to provide an ergonomic API for usage in web
//! through Web Assembly and in mobile devices through FFI.
//!
//! The goal is provide a easier and less verbose API to create, manage and interact with MLS
//! groups.
#![doc = include_str!(env!("STRIPPED_README_PATH"))]
#![cfg_attr(not(test), deny(missing_docs))]
#![allow(clippy::single_component_path_imports)]

#[cfg(test)]
#[macro_use]
pub mod test_utils;
// both imports above have to be defined at the beginning of the crate for rstest to work

mod build_metadata;
mod ephemeral;
mod error;
mod group_store;

/// re-export [rusty-jwt-tools](https://github.com/wireapp/rusty-jwt-tools) API
pub mod e2e_identity;
/// MLS Abstraction
pub mod mls;
/// Proteus Abstraction
#[cfg(feature = "proteus")]
pub mod proteus;
pub mod transaction_context;

pub use core_crypto_keystore::{ConnectionType, Database, DatabaseKey};
#[cfg(test)]
pub use core_crypto_macros::{dispotent, durable, idempotent};
pub use mls_crypto_provider::{EntropySeed, MlsCryptoProvider, RawEntropySeed};
pub use openmls::{
    group::{MlsGroup, MlsGroupConfig},
    prelude::{
        Ciphersuite as MlsCiphersuite, GroupEpoch, KeyPackage, KeyPackageIn, KeyPackageRef, MlsMessageIn, Node,
        SignatureScheme, group_info::VerifiableGroupInfo,
    },
};
#[cfg(feature = "proteus")]
use {async_lock::Mutex, std::sync::Arc};

pub use crate::{
    build_metadata::{BUILD_METADATA, BuildMetadata},
    e2e_identity::{
        E2eiEnrollment,
        device_status::DeviceStatus,
        identity::{WireIdentity, X509Identity},
        types::{E2eiAcmeChallenge, E2eiAcmeDirectory, E2eiNewAcmeAuthz, E2eiNewAcmeOrder},
    },
    ephemeral::{HISTORY_CLIENT_ID_PREFIX, HistorySecret},
    error::{
        Error, InnermostErrorMessage, KeystoreError, LeafError, MlsError, MlsErrorKind, ProteusError, ProteusErrorKind,
        RecursiveError, Result, ToRecursiveError,
    },
    mls::{
        ciphersuite::Ciphersuite,
        conversation::{
            ConversationId, MlsConversation,
            commit::MlsCommitBundle,
            config::{MlsConversationConfiguration, MlsCustomConfiguration, MlsWirePolicy},
            conversation_guard::decrypt::{MlsBufferedConversationDecryptMessage, MlsConversationDecryptMessage},
            group_info::{GroupInfoPayload, MlsGroupInfoBundle, MlsGroupInfoEncryptionType, MlsRatchetTreeType},
            proposal::MlsProposalBundle,
            welcome::WelcomeBundle,
        },
        credential::{
            Credential, CredentialRef, CredentialType, FindFilters as CredentialFindFilters, x509::CertificateBundle,
        },
        proposal::{MlsProposal, MlsProposalRef},
        session::{
            EpochObserver, HistoryObserver, Session,
            id::{ClientId, ClientIdRef},
            identifier::ClientIdentifier,
            key_package::{INITIAL_KEYING_MATERIAL_COUNT, KEYPACKAGE_DEFAULT_LIFETIME},
            user_id::UserId,
        },
    },
    transaction_context::e2e_identity::conversation_state::E2eiConversationState,
};

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

/// An entity / data which has been packaged by the application to be encrypted
/// and transmitted in an application message.
#[derive(Debug, derive_more::From, derive_more::Deref, serde::Serialize, serde::Deserialize)]
pub struct MlsTransportData(pub Vec<u8>);

/// Client callbacks to allow communication with the delivery service.
/// There are two different endpoints, one for messages and one for commit bundles.
#[cfg_attr(target_family = "wasm", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_family = "wasm"), async_trait::async_trait)]
pub trait MlsTransport: std::fmt::Debug + Send + Sync {
    /// Send a commit bundle to the corresponding endpoint.
    async fn send_commit_bundle(&self, commit_bundle: MlsCommitBundle) -> Result<MlsTransportResponse>;
    /// Send a message to the corresponding endpoint.
    async fn send_message(&self, mls_message: Vec<u8>) -> Result<MlsTransportResponse>;

    /// This function will be called before a history secret is sent to the mls transport to allow
    /// the application to package it in a suitable transport container (json, protobuf, ...).
    ///
    /// The `secret` parameter contain the history client's secrets which will be sent over the mls transport.
    ///
    /// Returns the history secret packaged for transport
    async fn prepare_for_transport(&self, secret: &HistorySecret) -> Result<MlsTransportData>;
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
