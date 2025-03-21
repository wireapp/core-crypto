#[cfg(target_family = "wasm")]
use wasm_bindgen::prelude::*;

#[derive(Debug, Clone, Eq, Hash, PartialEq, derive_more::From)]
#[cfg_attr(
    target_family = "wasm",
    wasm_bindgen,
    derive(serde::Serialize, serde::Deserialize),
    serde(from = "ClientIdSerializationShim", into = "ClientIdSerializationShim")
)]
pub struct ClientId(pub(crate) core_crypto::prelude::ClientId);

#[cfg(not(target_family = "wasm"))]
uniffi::custom_type!(ClientId, Vec<u8>, {
    lower: |id| id.0.to_vec(),
    try_lift: |vec| Ok(Self(vec.into()))
});

#[cfg(target_family = "wasm")]
#[wasm_bindgen]
impl ClientId {
    #[wasm_bindgen(constructor)]
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes.into())
    }

    pub fn as_bytes(&self) -> Vec<u8> {
        self.0.to_vec()
    }
}

pub type FfiClientId = Box<[u8]>;

#[cfg(target_family = "wasm")]
#[derive(serde::Serialize, serde::Deserialize)]
struct ClientIdSerializationShim(Vec<u8>);

#[cfg(target_family = "wasm")]
impl From<ClientId> for ClientIdSerializationShim {
    fn from(value: ClientId) -> Self {
        Self(value.0.into())
    }
}

#[cfg(target_family = "wasm")]
impl From<ClientIdSerializationShim> for ClientId {
    fn from(value: ClientIdSerializationShim) -> Self {
        Self(value.0.into())
    }
}

pub(crate) trait AsCoreCryptoClientId {
    fn as_cc_client_id(&self) -> core_crypto::prelude::ClientId;
}

impl AsCoreCryptoClientId for ClientId {
    fn as_cc_client_id(&self) -> core_crypto::prelude::ClientId {
        self.0.clone()
    }
}

impl AsCoreCryptoClientId for FfiClientId {
    fn as_cc_client_id(&self) -> core_crypto::prelude::ClientId {
        self.clone().into()
    }
}
