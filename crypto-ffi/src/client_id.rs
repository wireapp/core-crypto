#[cfg(target_family = "wasm")]
use wasm_bindgen::prelude::*;

#[derive(Debug, Clone, Eq, Hash, PartialEq, derive_more::From)]
#[cfg_attr(
    target_family = "wasm",
    wasm_bindgen,
    derive(serde::Serialize, serde::Deserialize),
    serde(from = "ClientIdSerializationShim", into = "ClientIdSerializationShim")
)]
#[cfg_attr(not(target_family = "wasm"), derive(uniffi::Object))]
pub struct ClientId(pub(crate) core_crypto::prelude::ClientId);

#[cfg(target_family = "wasm")]
pub(crate) type ClientIdMaybeArc = ClientId;

#[cfg(target_family = "wasm")]
pub(crate) fn client_id_from_cc(id: core_crypto::prelude::ClientId) -> ClientIdMaybeArc {
    ClientId(id)
}

#[cfg(not(target_family = "wasm"))]
pub(crate) type ClientIdMaybeArc = std::sync::Arc<ClientId>;

#[cfg(not(target_family = "wasm"))]
pub(crate) fn client_id_from_cc(id: core_crypto::prelude::ClientId) -> ClientIdMaybeArc {
    std::sync::Arc::new(crate::ClientId(id))
}

#[cfg_attr(target_family = "wasm", wasm_bindgen)]
#[cfg_attr(not(target_family = "wasm"), uniffi::export)]
impl ClientId {
    #[cfg_attr(target_family = "wasm", wasm_bindgen(constructor))]
    #[cfg_attr(not(target_family = "wasm"), uniffi::constructor)]
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes.into())
    }

    pub fn as_bytes(&self) -> Vec<u8> {
        self.0.to_vec()
    }
}

#[cfg(target_family = "wasm")]
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

#[cfg(target_family = "wasm")]
impl AsCoreCryptoClientId for FfiClientId {
    fn as_cc_client_id(&self) -> core_crypto::prelude::ClientId {
        self.clone().into()
    }
}
