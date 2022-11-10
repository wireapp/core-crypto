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
                config::{MlsConversationConfiguration, MlsCustomConfiguration, MlsWirePolicy},
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
        CoreCrypto, CoreCryptoCallbacks,
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
    fn authorize(&self, conversation_id: prelude::ConversationId, client_id: prelude::ClientId) -> bool;
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
        conversation_id: prelude::ConversationId,
        external_client_id: prelude::ClientId,
        existing_clients: Vec<prelude::ClientId>,
    ) -> bool;
    /// Validates if the given `client_id` belongs to one of the provided `existing_clients`
    /// This basically allows to defer the client ID parsing logic to the caller - because CoreCrypto is oblivious to such things
    ///
    /// # Arguments
    /// * `client_id` - client ID of the client referenced within the sent proposal
    /// * `existing_clients` - all the clients in the MLS group
    fn client_is_existing_group_user(
        &self,
        client_id: prelude::ClientId,
        existing_clients: Vec<prelude::ClientId>,
    ) -> bool;
}

#[derive(Debug)]
/// Wrapper superstruct for both [mls::MlsCentral] and [proteus::ProteusCentral]
/// As [std::ops::Deref] is implemented, this struct is automatically dereferred to [mls::MlsCentral] apart from `proteus_*` calls
pub struct CoreCrypto {
    mls: mls::MlsCentral,
    #[cfg(feature = "proteus")]
    proteus: Option<proteus::ProteusCentral>,
    #[cfg(not(feature = "proteus"))]
    #[allow(dead_code)]
    proteus: (),
}

impl From<mls::MlsCentral> for CoreCrypto {
    fn from(mls: mls::MlsCentral) -> Self {
        Self {
            mls,
            proteus: Default::default(),
        }
    }
}

impl std::ops::Deref for CoreCrypto {
    type Target = mls::MlsCentral;

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
    pub fn take(self) -> mls::MlsCentral {
        self.mls
    }
}
