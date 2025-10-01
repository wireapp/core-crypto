#[cfg(target_family = "wasm")]
use wasm_bindgen::prelude::*;

/// A Client identifier
///
/// A unique identifier for clients. A client is an identifier for each App a user is using, such as desktop,
/// mobile, etc. Users can have multiple clients.
/// More information [here](https://messaginglayersecurity.rocks/mls-architecture/draft-ietf-mls-architecture.html#name-group-members-and-clients)
#[derive(Debug, Clone, Eq, Hash, PartialEq, derive_more::From)]
#[cfg_attr(
    target_family = "wasm",
    wasm_bindgen,
    derive(serde::Serialize, serde::Deserialize),
    serde(from = "ClientIdSerializationShim", into = "ClientIdSerializationShim")
)]
#[cfg_attr(not(target_family = "wasm"), derive(uniffi::Object))]
pub struct ClientId(pub(crate) core_crypto::ClientId);

#[cfg(target_family = "wasm")]
pub(crate) type ClientIdMaybeArc = ClientId;

#[cfg(not(target_family = "wasm"))]
pub(crate) type ClientIdMaybeArc = std::sync::Arc<ClientId>;

#[cfg_attr(target_family = "wasm", wasm_bindgen)]
#[cfg_attr(not(target_family = "wasm"), uniffi::export)]
impl ClientId {
    /// Instantiate a client id from a byte array.
    #[cfg_attr(target_family = "wasm", wasm_bindgen(constructor))]
    #[cfg_attr(not(target_family = "wasm"), uniffi::constructor)]
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes.into())
    }

    /// Copy the id into a new byte array.
    #[cfg_attr(target_family = "wasm", wasm_bindgen(js_name = copyBytes))]
    pub fn copy_bytes(&self) -> Vec<u8> {
        self.0.to_vec()
    }
}

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

impl ClientId {
    pub(crate) fn as_cc(&self) -> core_crypto::ClientId {
        self.0.clone()
    }

    pub(crate) fn from_cc(id: core_crypto::ClientId) -> ClientIdMaybeArc {
        #[cfg(target_family = "wasm")]
        {
            ClientId(id)
        }

        #[cfg(not(target_family = "wasm"))]
        {
            std::sync::Arc::new(ClientId(id))
        }
    }
}
