use std::{sync::Arc, time::Duration};

use core_crypto::MlsCustomConfiguration;

use crate::{Ciphersuite, core_crypto_context::mls::ExternalSenderKey};

/// See [core_crypto::MlsWirePolicy]
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
#[repr(u8)]
pub enum WirePolicy {
    /// Handshake messages are never encrypted
    #[default]
    Plaintext = 1,
    /// Handshake messages are always encrypted
    Ciphertext = 2,
}

impl From<core_crypto::MlsWirePolicy> for WirePolicy {
    fn from(value: core_crypto::MlsWirePolicy) -> Self {
        match value {
            core_crypto::MlsWirePolicy::Plaintext => Self::Plaintext,
            core_crypto::MlsWirePolicy::Ciphertext => Self::Ciphertext,
        }
    }
}

impl From<WirePolicy> for core_crypto::MlsWirePolicy {
    fn from(value: WirePolicy) -> core_crypto::MlsWirePolicy {
        match value {
            WirePolicy::Plaintext => core_crypto::MlsWirePolicy::Plaintext,
            WirePolicy::Ciphertext => core_crypto::MlsWirePolicy::Ciphertext,
        }
    }
}

/// see [core_crypto::MlsCustomConfiguration]
#[derive(Debug, Default, Clone, Copy, uniffi::Record)]
pub struct CustomConfiguration {
    ///  Duration after which we will automatically force a self-update commit
    ///  Note: This isn't currently implemented
    pub key_rotation_span: Option<Duration>,

    /// Defines if handshake messages are encrypted or not
    /// Note: encrypted handshake messages are not supported by wire-server
    pub wire_policy: Option<WirePolicy>,
}

impl From<CustomConfiguration> for MlsCustomConfiguration {
    fn from(cfg: CustomConfiguration) -> Self {
        let key_rotation_span = cfg.key_rotation_span;

        let wire_policy = cfg.wire_policy.map(WirePolicy::into).unwrap_or_default();

        Self {
            key_rotation_span,
            wire_policy,
            ..Default::default()
        }
    }
}

/// The configuration parameters for a group/conversation
///
/// See [core_crypto::MlsConversationConfiguration]
#[derive(Debug, Clone, uniffi::Record)]
pub struct ConversationConfiguration {
    /// The ciphersuite used in the group
    pub ciphersuite: Option<Ciphersuite>,
    /// Delivery service public signature key and credential
    pub external_senders: Vec<Arc<ExternalSenderKey>>,
    /// Implementation specific configuration
    pub custom: CustomConfiguration,
}
