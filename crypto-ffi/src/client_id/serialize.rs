use std::sync::Arc;

use crate::{ClientId, DeviceId, Uuid};

/// This directly represents a `ClientId` of the `<userid>:<device-id>@<domain>` format.
/// Instantiate via [ClientId::deserialize].
#[derive(Debug, uniffi::Record, derive_more::Display)]
#[display(
    "{user_id}{}{device_id_hex}{}{domain}",
    core_crypto::ClientId::DELIMITER,
    core_crypto::ClientId::DOMAIN_SEPERATOR,
    device_id_hex = device_id.to_hex_string(),
)]
// only supported for records in uniffi >= 0.31. Remove condition after globally migrating to that version.
#[cfg_attr(any(feature = "wasm", feature = "napi"), uniffi::export(Display))]
pub struct DeserializedClientId {
    /// The client id this was deserialized from
    pub client_id: Arc<ClientId>,
    /// The user id component
    pub user_id: Arc<Uuid>,
    /// The device id component
    pub device_id: Arc<DeviceId>,
    /// The domain
    pub domain: String,
}

impl DeserializedClientId {
    pub(crate) fn new(client_id: ClientId) -> Self {
        let serialized = client_id.0.deserialize();
        Self {
            client_id: client_id.into(),
            user_id: Arc::new(serialized.user_id.into()),
            device_id: Arc::new(serialized.device_id.into()),
            domain: serialized.domain,
        }
    }
}
