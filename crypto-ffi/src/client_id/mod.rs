mod device_id;
mod serialize;
mod user_id;

use std::sync::Arc;

use wire_e2e_identity::E2eiClientId;

pub use crate::client_id::{device_id::DeviceId, serialize::DeserializedClientId, user_id::Uuid};

/// A unique identifier for an MLS client.
///
/// Each app instance a user is running, such as desktop or mobile, is a separate client
/// with its own client id. A single user may therefore have multiple clients.
/// More information: <https://messaginglayersecurity.rocks/mls-architecture/draft-ietf-mls-architecture.html#name-group-members-and-clients>
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    Hash,
    derive_more::From,
    derive_more::Into,
    derive_more::Deref,
    derive_more::DerefMut,
    uniffi::Object,
)]
#[uniffi::export(Eq, Hash)]
pub struct ClientId(core_crypto::ClientId);

impl AsRef<core_crypto::ClientIdRef> for ClientId {
    fn as_ref(&self) -> &core_crypto::ClientIdRef {
        core_crypto::ClientIdRef::new(&self.0)
    }
}

#[uniffi::export]
impl ClientId {
    /// Create a new client id.
    #[uniffi::constructor]
    pub fn new(user_id: Arc<crate::Uuid>, device_id: Arc<DeviceId>, domain: String) -> Self {
        let inner = core_crypto::ClientId::new(**user_id, **device_id, &domain);
        Self(inner)
    }

    /// Copy the wrapped data into a direct representation of the `<user-id>:<device-id>@<domain>` format.
    pub fn deserialize(&self) -> DeserializedClientId {
        DeserializedClientId::new(self.clone())
    }

    /// Copy the wrapped data into a new byte array.
    pub fn copy_bytes(&self) -> Vec<u8> {
        self.0.clone().into()
    }
}

impl ClientId {
    pub(crate) fn as_e2ei_client_id(&self) -> E2eiClientId {
        self.0.as_e2ei_client_id()
    }
}
