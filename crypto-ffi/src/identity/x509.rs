#[cfg(target_family = "wasm")]
use wasm_bindgen::prelude::*;

/// See [core_crypto::prelude::X509Identity]
#[derive(Debug, Clone)]
#[cfg_attr(
    target_family = "wasm",
    wasm_bindgen(getter_with_clone),
    derive(serde::Serialize, serde::Deserialize)
)]
#[cfg_attr(not(target_family = "wasm"), derive(uniffi::Record))]
pub struct X509Identity {
    pub handle: String,
    pub display_name: String,
    pub domain: String,
    pub certificate: String,
    pub serial_number: String,
    pub not_before: u64,
    pub not_after: u64,
}

impl From<core_crypto::prelude::X509Identity> for X509Identity {
    fn from(i: core_crypto::prelude::X509Identity) -> Self {
        Self {
            handle: i.handle,
            display_name: i.display_name,
            domain: i.domain,
            certificate: i.certificate,
            serial_number: i.serial_number,
            not_before: i.not_before,
            not_after: i.not_after,
        }
    }
}
