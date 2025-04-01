#[cfg(target_family = "wasm")]
use wasm_bindgen::prelude::*;

use core_crypto::prelude::MlsCustomConfiguration;

use crate::Ciphersuite;

/// See [core_crypto::prelude::MlsWirePolicy]
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

impl From<core_crypto::prelude::MlsWirePolicy> for WirePolicy {
    fn from(value: core_crypto::prelude::MlsWirePolicy) -> Self {
        match value {
            core_crypto::prelude::MlsWirePolicy::Plaintext => Self::Plaintext,
            core_crypto::prelude::MlsWirePolicy::Ciphertext => Self::Ciphertext,
        }
    }
}

impl From<WirePolicy> for core_crypto::prelude::MlsWirePolicy {
    fn from(value: WirePolicy) -> core_crypto::prelude::MlsWirePolicy {
        match value {
            WirePolicy::Plaintext => core_crypto::prelude::MlsWirePolicy::Plaintext,
            WirePolicy::Ciphertext => core_crypto::prelude::MlsWirePolicy::Ciphertext,
        }
    }
}

/// see [core_crypto::prelude::MlsCustomConfiguration]
#[derive(Debug, Default, Clone, Copy)]
#[cfg_attr(target_family = "wasm", wasm_bindgen, derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(not(target_family = "wasm"), derive(uniffi::Record))]
pub struct CustomConfiguration {
    ///  Duration in seconds after which we will automatically force a self-update commit
    ///  Note: This isn't currently implemented
    #[cfg_attr(target_family = "wasm", wasm_bindgen(js_name = "keyRotationSpan"))]
    pub key_rotation_span: Option<u32>,
    /// Defines if handshake messages are encrypted or not
    /// Note: encrypted handshake messages are not supported by wire-server
    #[cfg_attr(target_family = "wasm", wasm_bindgen(js_name = "wirePolicy"))]
    pub wire_policy: Option<WirePolicy>,
}

#[cfg(target_family = "wasm")]
#[wasm_bindgen]
impl CustomConfiguration {
    #[wasm_bindgen(constructor)]
    pub fn new(key_rotation_span: Option<u32>, wire_policy: Option<WirePolicy>) -> Self {
        Self {
            key_rotation_span,
            wire_policy,
        }
    }
}

#[cfg(not(target_family = "wasm"))]
#[uniffi::export]
impl CustomConfiguration {
    #[uniffi::constructor]
    pub fn new(key_rotation_span: Option<u32>, wire_policy: Option<WirePolicy>) -> Self {
        Self {
            key_rotation_span,
            wire_policy,
        }
    }
}

impl From<CustomConfiguration> for MlsCustomConfiguration {
    fn from(cfg: CustomConfiguration) -> Self {
        let key_rotation_span = cfg
            .key_rotation_span
            .map(|span| std::time::Duration::from_secs(span as u64));
        let wire_policy = cfg.wire_policy.map(WirePolicy::into).unwrap_or_default();
        Self {
            key_rotation_span,
            wire_policy,
            ..Default::default()
        }
    }
}

/// See [core_crypto::prelude::MlsConversationConfiguration]
#[derive(Debug, Clone)]
#[cfg_attr(
    target_family = "wasm",
    wasm_bindgen(getter_with_clone),
    derive(serde::Serialize, serde::Deserialize)
)]
#[cfg_attr(not(target_family = "wasm"), derive(uniffi::Record))]
pub struct ConversationConfiguration {
    pub(crate) ciphersuite: Ciphersuite,
    pub(crate) external_senders: Vec<Vec<u8>>,
    pub(crate) custom: CustomConfiguration,
}

#[cfg(target_family = "wasm")]
#[wasm_bindgen]
impl ConversationConfiguration {
    #[wasm_bindgen(constructor)]
    pub fn new(
        ciphersuite: Ciphersuite,
        external_senders: Vec<js_sys::Uint8Array>,
        custom: Option<CustomConfiguration>,
    ) -> Self {
        let external_senders = external_senders.iter().map(js_sys::Uint8Array::to_vec).collect();
        let custom = custom.unwrap_or_default();
        Self {
            ciphersuite,
            external_senders,
            custom,
        }
    }
}

#[cfg(not(target_family = "wasm"))]
#[uniffi::export]
impl ConversationConfiguration {
    #[uniffi::constructor(default(custom = None))]
    pub fn new(ciphersuite: Ciphersuite, external_senders: Vec<Vec<u8>>, custom: Option<CustomConfiguration>) -> Self {
        let custom = custom.unwrap_or_default();
        Self {
            ciphersuite,
            external_senders,
            custom,
        }
    }
}
