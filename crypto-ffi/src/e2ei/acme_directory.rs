#[cfg(target_family = "wasm")]
use wasm_bindgen::prelude::*;

/// Holds URLs of all the standard ACME endpoint supported on an ACME server.
///
/// - See https://www.rfc-editor.org/rfc/rfc8555.html#section-7.1.1
/// - See [core_crypto::e2e_identity::types::E2eiAcmeDirectory]
#[derive(Debug)]
#[cfg_attr(
    target_family = "wasm",
    wasm_bindgen(getter_with_clone),
    derive(serde::Serialize, serde::Deserialize)
)]
#[cfg_attr(not(target_family = "wasm"), derive(uniffi::Record))]
pub struct AcmeDirectory {
    /// URL for fetching a new nonce. Use this only for creating a new account.
    #[cfg_attr(target_family = "wasm", wasm_bindgen(readonly))]
    pub new_nonce: String,
    /// URL for creating a new account.
    #[cfg_attr(target_family = "wasm", wasm_bindgen(readonly))]
    pub new_account: String,
    /// URL for creating a new order.
    #[cfg_attr(target_family = "wasm", wasm_bindgen(readonly))]
    pub new_order: String,
    /// Revocation URL
    #[cfg_attr(target_family = "wasm", wasm_bindgen(readonly))]
    pub revoke_cert: String,
}

impl From<core_crypto::prelude::E2eiAcmeDirectory> for AcmeDirectory {
    fn from(directory: core_crypto::prelude::E2eiAcmeDirectory) -> Self {
        Self {
            new_nonce: directory.new_nonce,
            new_account: directory.new_account,
            new_order: directory.new_order,
            revoke_cert: directory.revoke_cert,
        }
    }
}

impl From<AcmeDirectory> for core_crypto::prelude::E2eiAcmeDirectory {
    fn from(directory: AcmeDirectory) -> Self {
        Self {
            new_nonce: directory.new_nonce,
            new_account: directory.new_account,
            new_order: directory.new_order,
            revoke_cert: directory.revoke_cert,
        }
    }
}
