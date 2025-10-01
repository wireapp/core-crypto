#[cfg(not(target_family = "wasm"))]
use std::time::Duration;

use core_crypto::MlsCustomConfiguration;
#[cfg(target_family = "wasm")]
use wasm_bindgen::prelude::*;

use crate::{Ciphersuite, core_crypto_context::mls::ExternalSenderKeyMaybeArc};

/// See [core_crypto::MlsWirePolicy]
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(target_family = "wasm", wasm_bindgen, derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(not(target_family = "wasm"), derive(uniffi::Enum))]
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
#[derive(Debug, Default, Clone, Copy)]
#[cfg_attr(target_family = "wasm", wasm_bindgen, derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(not(target_family = "wasm"), derive(uniffi::Record))]
pub struct CustomConfiguration {
    ///  Duration in seconds after which we will automatically force a self-update commit
    ///  Note: This isn't currently implemented
    #[cfg(target_family = "wasm")]
    #[wasm_bindgen(js_name = "keyRotationSpan")]
    pub key_rotation_span: Option<u32>,

    ///  Duration after which we will automatically force a self-update commit
    ///  Note: This isn't currently implemented
    #[cfg(not(target_family = "wasm"))]
    pub key_rotation_span: Option<Duration>,

    /// Defines if handshake messages are encrypted or not
    /// Note: encrypted handshake messages are not supported by wire-server
    #[cfg_attr(target_family = "wasm", wasm_bindgen(js_name = "wirePolicy"))]
    pub wire_policy: Option<WirePolicy>,
}

impl From<CustomConfiguration> for MlsCustomConfiguration {
    fn from(cfg: CustomConfiguration) -> Self {
        #[cfg(target_family = "wasm")]
        let key_rotation_span = cfg
            .key_rotation_span
            .map(Into::into)
            .map(std::time::Duration::from_secs);

        #[cfg(not(target_family = "wasm"))]
        let key_rotation_span = cfg.key_rotation_span;

        let wire_policy = cfg.wire_policy.map(WirePolicy::into).unwrap_or_default();

        Self {
            key_rotation_span,
            wire_policy,
            ..Default::default()
        }
    }
}

#[cfg(target_family = "wasm")]
#[wasm_bindgen]
impl CustomConfiguration {
    /// Construct a `CustomConfiguration` from its parts.
    #[wasm_bindgen(constructor)]
    pub fn new(key_rotation_span: Option<u32>, wire_policy: Option<WirePolicy>) -> Self {
        Self {
            key_rotation_span,
            wire_policy,
        }
    }
}

/// The configuration parameters for a group/conversation
///
/// See [core_crypto::MlsConversationConfiguration]
#[derive(Debug, Clone)]
#[cfg_attr(
    target_family = "wasm",
    wasm_bindgen(getter_with_clone),
    derive(serde::Serialize, serde::Deserialize)
)]
#[cfg_attr(not(target_family = "wasm"), derive(uniffi::Record))]
pub struct ConversationConfiguration {
    /// The ciphersuite used in the group
    #[cfg_attr(target_family = "wasm", wasm_bindgen(readonly))]
    pub ciphersuite: Option<Ciphersuite>,
    /// Delivery service public signature key and credential
    #[cfg_attr(target_family = "wasm", wasm_bindgen(readonly, js_name=externalSenders))]
    pub external_senders: Vec<ExternalSenderKeyMaybeArc>,
    /// Implementation specific configuration
    #[cfg_attr(target_family = "wasm", wasm_bindgen(readonly))]
    pub custom: CustomConfiguration,
}

#[cfg(target_family = "wasm")]
#[wasm_bindgen]
impl ConversationConfiguration {
    /// Construct a `ConversationConfiguration` from its parts.
    #[wasm_bindgen(constructor)]
    pub fn new(
        ciphersuite: Option<Ciphersuite>,
        external_senders: Option<Vec<ExternalSenderKeyMaybeArc>>,
        key_rotation_span: Option<u32>,
        wire_policy: Option<WirePolicy>,
    ) -> crate::CoreCryptoResult<ConversationConfiguration> {
        let external_senders = external_senders.unwrap_or_default();
        Ok(Self {
            ciphersuite,
            external_senders,
            custom: CustomConfiguration {
                key_rotation_span,
                wire_policy,
            },
        })
    }
}
