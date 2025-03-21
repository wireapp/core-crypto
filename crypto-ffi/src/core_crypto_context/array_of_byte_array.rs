use js_sys::Uint8Array;
use wasm_bindgen::prelude::*;

/// We need in a few places to move `Vec<Vec<u8>>` back and forth across the FFI boundary.
/// Unfortunately, `wasm_bindgen` doesn't like to do that natively. So this struct
/// bridges that gap.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[wasm_bindgen]
pub struct ArrayOfByteArray(Vec<Vec<u8>>);

impl ArrayOfByteArray {
    pub fn into_inner(self) -> Vec<Vec<u8>> {
        self.0
    }
}

impl From<Vec<Vec<u8>>> for ArrayOfByteArray {
    fn from(value: Vec<Vec<u8>>) -> Self {
        Self(value)
    }
}

impl FromIterator<Vec<u8>> for ArrayOfByteArray {
    fn from_iter<T: IntoIterator<Item = Vec<u8>>>(iter: T) -> Self {
        iter.into_iter().collect::<Vec<_>>().into()
    }
}

impl From<ArrayOfByteArray> for Vec<Vec<u8>> {
    fn from(value: ArrayOfByteArray) -> Self {
        value.0
    }
}

impl AsRef<Vec<Vec<u8>>> for ArrayOfByteArray {
    fn as_ref(&self) -> &Vec<Vec<u8>> {
        &self.0
    }
}

impl From<Vec<Uint8Array>> for ArrayOfByteArray {
    fn from(value: Vec<Uint8Array>) -> Self {
        Self(value.iter().map(Uint8Array::to_vec).collect::<Vec<_>>())
    }
}

impl From<ArrayOfByteArray> for Vec<Uint8Array> {
    fn from(value: ArrayOfByteArray) -> Self {
        value
            .into_inner()
            .iter()
            .map(Vec::as_slice)
            .map(Uint8Array::from)
            .collect()
    }
}

#[wasm_bindgen]
impl ArrayOfByteArray {
    #[wasm_bindgen(constructor)]
    pub fn new(aoba: Vec<Uint8Array>) -> Self {
        aoba.into()
    }

    pub fn as_arrays(&self) -> Vec<Uint8Array> {
        self.0.iter().map(Vec::as_slice).map(Uint8Array::from).collect()
    }
}
