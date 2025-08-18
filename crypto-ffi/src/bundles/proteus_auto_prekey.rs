#[cfg(target_family = "wasm")]
use wasm_bindgen::prelude::*;

/// Encapsulates a prekey id and a cbor-serialized prekey
#[derive(Debug, Clone)]
#[cfg_attr(
    target_family = "wasm",
    wasm_bindgen(getter_with_clone),
    derive(serde::Serialize, serde::Deserialize)
)]
#[cfg_attr(not(target_family = "wasm"), derive(uniffi::Record))]
pub struct ProteusAutoPrekeyBundle {
    /// Prekey id (automatically incremented)
    #[cfg_attr(target_family = "wasm", wasm_bindgen(readonly))]
    pub id: u16,
    /// CBOR serialization of prekey
    #[cfg_attr(target_family = "wasm", wasm_bindgen(readonly))]
    pub pkb: Vec<u8>,
}
