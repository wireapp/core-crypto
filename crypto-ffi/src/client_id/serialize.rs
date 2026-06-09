use std::sync::Arc;

use crate::ClientId;

/// This directlry represents a `ClientId` of the `<userid>-<device-id>@<domain>` format.
/// Instantiate via [ClientId::deserialize].
#[derive(Debug, uniffi::Record)]
pub struct DeserializedClientId {
    /// The client id this was deserialized from
    pub client_id: Arc<ClientId>,
    /// The string representation of a UUID
    pub user_id: String,
    /// A hex-encoded unsigned 64-bit integer
    pub device_id: String,
    /// The domain
    pub domain: String,
}

impl DeserializedClientId {
    pub(crate) fn new(client_id: ClientId) -> Self {
        let serialized = client_id.0.deserialize();
        Self {
            client_id: client_id.into(),
            user_id: serialized.user_id.hyphenated().to_string(),
            device_id: serialized.device_id,
            domain: serialized.domain,
        }
    }
}
