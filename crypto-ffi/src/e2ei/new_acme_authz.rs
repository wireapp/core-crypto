#[cfg(target_family = "wasm")]
use wasm_bindgen::prelude::*;

use crate::AcmeChallenge;

/// Result of an authorization creation.
///
/// - See <https://www.rfc-editor.org/rfc/rfc8555.html#section-7.5>
/// - See [core_crypto::e2e_identity::types::E2eiNewAcmeAuthz]
#[derive(Debug)]
#[cfg_attr(
    target_family = "wasm",
    wasm_bindgen(getter_with_clone),
    derive(serde::Serialize, serde::Deserialize)
)]
#[cfg_attr(not(target_family = "wasm"), derive(uniffi::Record))]
pub struct NewAcmeAuthz {
    /// DNS entry associated with those challenge
    #[cfg_attr(target_family = "wasm", wasm_bindgen(readonly))]
    pub identifier: String,
    /// ACME challenge + ACME key thumbprint
    #[cfg_attr(target_family = "wasm", wasm_bindgen(readonly))]
    pub keyauth: Option<String>,
    /// Associated ACME Challenge
    #[cfg_attr(target_family = "wasm", wasm_bindgen(readonly))]
    pub challenge: AcmeChallenge,
}

impl From<core_crypto::prelude::E2eiNewAcmeAuthz> for NewAcmeAuthz {
    fn from(new_authz: core_crypto::prelude::E2eiNewAcmeAuthz) -> Self {
        Self {
            identifier: new_authz.identifier,
            keyauth: new_authz.keyauth,
            challenge: new_authz.challenge.into(),
        }
    }
}

impl From<NewAcmeAuthz> for core_crypto::prelude::E2eiNewAcmeAuthz {
    fn from(new_authz: NewAcmeAuthz) -> Self {
        Self {
            identifier: new_authz.identifier,
            keyauth: new_authz.keyauth,
            challenge: new_authz.challenge.into(),
        }
    }
}
