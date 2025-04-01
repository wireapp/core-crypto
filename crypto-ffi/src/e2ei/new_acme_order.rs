#[cfg(target_family = "wasm")]
use wasm_bindgen::prelude::*;

/// Result of an order creation.
///
/// - See https://www.rfc-editor.org/rfc/rfc8555.html#section-7.4
/// - See [core_crypto::e2e_identity::types::E2eiNewAcmeOrder]
#[derive(Debug)]
#[cfg_attr(
    target_family = "wasm",
    wasm_bindgen(getter_with_clone),
    derive(serde::Serialize, serde::Deserialize)
)]
#[cfg_attr(not(target_family = "wasm"), derive(uniffi::Record))]
pub struct NewAcmeOrder {
    #[cfg_attr(target_family = "wasm", wasm_bindgen(readonly))]
    pub delegate: Vec<u8>,
    #[cfg_attr(target_family = "wasm", wasm_bindgen(readonly))]
    pub authorizations: Vec<String>,
}

impl From<core_crypto::prelude::E2eiNewAcmeOrder> for NewAcmeOrder {
    fn from(new_order: core_crypto::prelude::E2eiNewAcmeOrder) -> Self {
        Self {
            delegate: new_order.delegate,
            authorizations: new_order.authorizations,
        }
    }
}

impl From<NewAcmeOrder> for core_crypto::prelude::E2eiNewAcmeOrder {
    fn from(new_order: NewAcmeOrder) -> Self {
        Self {
            delegate: new_order.delegate,
            authorizations: new_order.authorizations,
        }
    }
}
