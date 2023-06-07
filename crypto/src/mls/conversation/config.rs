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

//! Conversation configuration.
//!
//! Either use [MlsConversationConfiguration] when creating a conversation or [MlsCustomConfiguration]
//! when joining one by Welcome or external commit

use openmls::prelude::{
    Credential, ExternalSender, SenderRatchetConfiguration, SignaturePublicKey, WireFormatPolicy,
    PURE_CIPHERTEXT_WIRE_FORMAT_POLICY, PURE_PLAINTEXT_WIRE_FORMAT_POLICY,
};
use serde::{Deserialize, Serialize};

use crate::{mls::MlsCiphersuite, CryptoResult};

/// Sets the config in OpenMls for the oldest possible epoch(past current) that a message can be decrypted
pub(crate) const MAX_PAST_EPOCHS: usize = 2;

/// The configuration parameters for a group/conversation
#[derive(Debug, Clone, Default)]
pub struct MlsConversationConfiguration {
    /// The `OpenMls` Ciphersuite used in the group
    pub ciphersuite: MlsCiphersuite,
    /// Delivery service public signature key and credential
    pub external_senders: Vec<ExternalSender>,
    /// Implementation specific configuration
    pub custom: MlsCustomConfiguration,
}

impl MlsConversationConfiguration {
    // TODO: pending a long term solution with a real certificate
    const WIRE_SERVER_IDENTITY: &'static str = "wire-server";
    const PADDING_SIZE: usize = 128;

    /// Generates an `MlsGroupConfig` from this configuration
    #[inline(always)]
    pub fn as_openmls_default_configuration(&self) -> CryptoResult<openmls::group::MlsGroupConfig> {
        Ok(openmls::group::MlsGroupConfig::builder()
            .wire_format_policy(self.custom.wire_policy.into())
            .max_past_epochs(MAX_PAST_EPOCHS)
            .padding_size(Self::PADDING_SIZE)
            .number_of_resumption_psks(1)
            .sender_ratchet_configuration(SenderRatchetConfiguration::new(
                self.custom.out_of_order_tolerance,
                self.custom.maximum_forward_distance,
            ))
            .use_ratchet_tree_extension(true)
            .external_senders(self.external_senders.clone())
            .build())
    }

    /// Parses supplied key from Delivery Service in order to build back an [ExternalSender]
    /// Note that this only works currently with Ed25519 keys and will have to be changed to accept
    /// other key schemes
    pub fn set_raw_external_senders(&mut self, external_senders: Vec<Vec<u8>>) {
        self.external_senders = external_senders
            .into_iter()
            .map(|key| {
                ExternalSender::new(
                    SignaturePublicKey::from(key),
                    Credential::new_basic(Self::WIRE_SERVER_IDENTITY.into()),
                )
            })
            .collect();
    }
}

/// The configuration parameters for a group/conversation which are not handled natively by openmls
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MlsCustomConfiguration {
    // TODO: Not implemented yet
    /// Duration in seconds after which we will automatically force a self_update commit
    pub key_rotation_span: Option<std::time::Duration>,
    /// Defines if handshake messages are encrypted or not
    pub wire_policy: MlsWirePolicy,
    /// Window for which decryption secrets are kept within an epoch. Use this with caution since
    /// this affects forward secrecy within an epoch. Use this when the Delivery Service cannot
    /// guarantee application messages order.
    pub out_of_order_tolerance: u32,
    /// How many application messages can be skipped. Use this when the Delivery Service can drop
    /// application messages
    pub maximum_forward_distance: u32,
}

impl Default for MlsCustomConfiguration {
    fn default() -> Self {
        Self {
            wire_policy: MlsWirePolicy::Plaintext,
            key_rotation_span: Default::default(),
            out_of_order_tolerance: 2,
            maximum_forward_distance: 1000,
        }
    }
}

/// Wrapper over [WireFormatPolicy](openmls::prelude::WireFormatPolicy)
#[derive(Debug, Copy, Clone, Default, Eq, PartialEq, Serialize, Deserialize)]
#[repr(u8)]
pub enum MlsWirePolicy {
    /// Handshake messages are never encrypted
    #[default]
    Plaintext = 1,
    /// Handshake messages are always encrypted
    Ciphertext = 2,
}

impl From<MlsWirePolicy> for WireFormatPolicy {
    fn from(policy: MlsWirePolicy) -> Self {
        match policy {
            MlsWirePolicy::Ciphertext => PURE_CIPHERTEXT_WIRE_FORMAT_POLICY,
            MlsWirePolicy::Plaintext => PURE_PLAINTEXT_WIRE_FORMAT_POLICY,
        }
    }
}
