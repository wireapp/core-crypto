#[cfg(target_family = "wasm")]
use wasm_bindgen::prelude::*;

#[cfg(not(target_family = "wasm"))]
use crate::Timestamp;

/// Represents the parts of [WireIdentity][crate::WireIdentity] that are specific to a X509 certificate (and not a Basic one).
///
/// We don't use an enum here since the sole purpose of this is to be exposed through the FFI (and
/// union types are impossible to carry over the FFI boundary)
#[derive(Debug, Clone)]
#[cfg_attr(
    target_family = "wasm",
    wasm_bindgen(getter_with_clone),
    derive(serde::Serialize, serde::Deserialize)
)]
#[cfg_attr(not(target_family = "wasm"), derive(uniffi::Record))]
pub struct X509Identity {
    /// user handle e.g. `john_wire`
    #[cfg_attr(target_family = "wasm", wasm_bindgen(readonly))]
    pub handle: String,
    /// Name as displayed in the messaging application e.g. `John Fitzgerald Kennedy`
    #[cfg_attr(target_family = "wasm", wasm_bindgen(readonly, js_name = displayName))]
    pub display_name: String,
    /// DNS domain for which this identity proof was generated e.g. `whitehouse.gov`
    #[cfg_attr(target_family = "wasm", wasm_bindgen(readonly))]
    pub domain: String,
    /// X509 certificate identifying this client in the MLS group ; PEM encoded
    #[cfg_attr(target_family = "wasm", wasm_bindgen(readonly))]
    pub certificate: String,
    /// X509 certificate serial number
    #[cfg_attr(target_family = "wasm", wasm_bindgen(readonly, js_name = serialNumber))]
    pub serial_number: String,

    /// X509 certificate not before as Unix timestamp
    #[cfg(target_family = "wasm")]
    #[wasm_bindgen(readonly, js_name = notBefore)]
    pub not_before: u64,

    /// X509 certificate not before
    #[cfg(not(target_family = "wasm"))]
    pub not_before: Timestamp,

    /// X509 certificate not after as Unix timestamp
    #[cfg(target_family = "wasm")]
    #[wasm_bindgen(readonly, js_name = notAfter)]
    pub not_after: u64,

    /// X509 certificate not after
    #[cfg(not(target_family = "wasm"))]
    pub not_after: Timestamp,
}

impl From<core_crypto::prelude::X509Identity> for X509Identity {
    fn from(i: core_crypto::prelude::X509Identity) -> Self {
        #[cfg(target_family = "wasm")]
        let not_before = i.not_before;

        #[cfg(target_family = "wasm")]
        let not_after = i.not_after;

        #[cfg(not(target_family = "wasm"))]
        let not_before = Timestamp::from_epoch_secs(i.not_before);

        #[cfg(not(target_family = "wasm"))]
        let not_after = Timestamp::from_epoch_secs(i.not_after);

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
