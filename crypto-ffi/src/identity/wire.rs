#[cfg(target_family = "wasm")]
use wasm_bindgen::prelude::*;

use crate::{CredentialType, DeviceStatus, X509Identity};

/// See [core_crypto::prelude::WireIdentity]
#[derive(Debug, Clone)]
#[cfg_attr(
    target_family = "wasm",
    wasm_bindgen(getter_with_clone),
    derive(serde::Serialize, serde::Deserialize)
)]
#[cfg_attr(not(target_family = "wasm"), derive(uniffi::Record))]
pub struct WireIdentity {
    /// Unique client identifier e.g. `T4Coy4vdRzianwfOgXpn6A:6add501bacd1d90e@whitehouse.gov`
    pub client_id: String,
    /// Status of the Credential at the moment this object is created
    pub status: DeviceStatus,
    /// MLS thumbprint
    pub thumbprint: String,
    pub credential_type: CredentialType,
    pub x509_identity: Option<X509Identity>,
}

impl From<core_crypto::prelude::WireIdentity> for WireIdentity {
    fn from(i: core_crypto::prelude::WireIdentity) -> Self {
        Self {
            client_id: i.client_id,
            status: i.status.into(),
            thumbprint: i.thumbprint,
            credential_type: i.credential_type.into(),
            x509_identity: i.x509_identity.map(Into::into),
        }
    }
}
