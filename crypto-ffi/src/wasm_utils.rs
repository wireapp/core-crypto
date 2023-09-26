#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ArrayOfByteArray(pub Vec<Vec<u8>>);

impl From<Vec<Vec<u8>>> for ArrayOfByteArray {
    fn from(value: Vec<Vec<u8>>) -> Self {
        Self(value)
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

impl From<Vec<js_sys::Uint8Array>> for ArrayOfByteArray {
    fn from(value: Vec<js_sys::Uint8Array>) -> Self {
        Self(value.iter().map(js_sys::Uint8Array::to_vec).collect::<Vec<_>>())
    }
}

impl From<ArrayOfByteArray> for Vec<js_sys::Uint8Array> {
    fn from(value: ArrayOfByteArray) -> Self {
        value
            .0
            .iter()
            .map(Vec::as_slice)
            .map(js_sys::Uint8Array::from)
            .collect::<Vec<_>>()
    }
}
