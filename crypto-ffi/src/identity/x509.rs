#[cfg(target_family = "wasm")]
use wasm_bindgen::prelude::*;

#[cfg(not(target_family = "wasm"))]
use std::time::{Duration, SystemTime};

/// See [core_crypto::prelude::X509Identity]
#[derive(Debug, Clone)]
#[cfg_attr(
    target_family = "wasm",
    wasm_bindgen(getter_with_clone),
    derive(serde::Serialize, serde::Deserialize)
)]
#[cfg_attr(not(target_family = "wasm"), derive(uniffi::Record))]
pub struct X509Identity {
    #[cfg_attr(target_family = "wasm", wasm_bindgen(readonly))]
    pub handle: String,
    #[cfg_attr(target_family = "wasm", wasm_bindgen(readonly, js_name = displayName))]
    pub display_name: String,
    #[cfg_attr(target_family = "wasm", wasm_bindgen(readonly))]
    pub domain: String,
    #[cfg_attr(target_family = "wasm", wasm_bindgen(readonly))]
    pub certificate: String,
    #[cfg_attr(target_family = "wasm", wasm_bindgen(readonly, js_name = serialNumber))]
    pub serial_number: String,

    #[cfg(target_family = "wasm")]
    #[wasm_bindgen(readonly, js_name = notBefore)]
    pub not_before: u64,

    #[cfg(not(target_family = "wasm"))]
    pub not_before: SystemTime,

    #[cfg(target_family = "wasm")]
    #[wasm_bindgen(readonly, js_name = notAfter)]
    pub not_after: u64,

    #[cfg(not(target_family = "wasm"))]
    pub not_after: SystemTime,
}

impl From<core_crypto::prelude::X509Identity> for X509Identity {
    fn from(i: core_crypto::prelude::X509Identity) -> Self {
        #[cfg(target_family = "wasm")]
        let not_before = i.not_before;

        #[cfg(target_family = "wasm")]
        let not_after = i.not_after;

        #[cfg(not(target_family = "wasm"))]
        let not_before = SystemTime::UNIX_EPOCH + Duration::from_secs(i.not_before);

        #[cfg(not(target_family = "wasm"))]
        let not_after = SystemTime::UNIX_EPOCH + Duration::from_secs(i.not_after);

        Self {
            handle: i.handle,
            display_name: i.display_name,
            domain: i.domain,
            certificate: i.certificate,
            serial_number: i.serial_number,
            not_before,
            not_after,
        }
    }
}
