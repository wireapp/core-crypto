use std::sync::Arc;

use crate::{ClientId, DeviceId, Uuid};

/// This directly represents a `ClientId` of the `<userid>:<device-id>@<domain>` format.
/// Instantiate via [ClientId::deserialize].
///
/// Its `Display` reproduces the bytes of the [`ClientId`] it came from, so the device id is
/// rendered as unpadded hex. Note that this differs from [`DeviceId::to_hex_string`], which is
/// fixed-width: a client id is not a hex-encoded binary value, and only the unpadded form matches
/// what an E2EI certificate carries.
#[derive(Debug, uniffi::Record, derive_more::Display)]
#[display(
    "{user_id}{}{device_id_hex}{}{domain}",
    core_crypto::ClientId::DELIMITER,
    core_crypto::ClientId::DOMAIN_SEPERATOR,
    device_id_hex = core_crypto::ClientId::encode_device_id(device_id.to_u64()),
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

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use crate::{ClientId, DeviceId, Uuid};

    /// `Display` has to reproduce the client id it was deserialized from, including when the
    /// device id's leading nibbles are zero. It previously rendered the device id fixed-width,
    /// which does not match the client id, nor the `wireapp://` SAN of an E2EI certificate.
    #[test]
    fn display_round_trips_the_client_id() {
        let user_id = Arc::new(Uuid::new("b01ec765-db9d-4502-9859-a9fa8c437c6f").unwrap());

        for device_id in [
            0x0u64,
            0xf,
            0x00ff,
            0x03e7_98f8_29a2_1f2a,
            0x8e64_2443_0d3b_28be,
            u64::MAX,
        ] {
            let client_id = ClientId::new(
                user_id.clone(),
                Arc::new(DeviceId::new(device_id)),
                "wire.com".to_string(),
            );
            let expected = String::from_utf8(client_id.copy_bytes()).unwrap();

            assert_eq!(
                client_id.deserialize().to_string(),
                expected,
                "rendering a deserialized client id must reproduce the client id"
            );
        }
    }
}
