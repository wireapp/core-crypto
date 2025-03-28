#[cfg(target_family = "wasm")]
use wasm_bindgen::prelude::*;

#[derive(Debug, Clone)]
#[cfg_attr(
    target_family = "wasm",
    wasm_bindgen(getter_with_clone),
    derive(serde::Serialize, serde::Deserialize)
)]
#[cfg_attr(not(target_family = "wasm"), derive(uniffi::Record))]
pub struct ProteusAutoPrekeyBundle {
    #[cfg_attr(target_family = "wasm", wasm_bindgen(readonly))]
    pub id: u16,
    #[cfg_attr(target_family = "wasm", wasm_bindgen(readonly))]
    pub pkb: Vec<u8>,
}
