use crate::{CoreCryptoError, CoreCryptoResult};

#[derive(
    Debug,
    Clone,
    Copy,
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
/// A Device ID.
pub struct DeviceId(u64);

#[uniffi::export]
impl DeviceId {
    /// New device id from an unsigned 64-bit integer.
    #[uniffi::constructor]
    pub fn new(id: u64) -> Self {
        Self(id)
    }

    /// Construct a `DeviceId` from 8 bytes encoded as a hex string.
    #[uniffi::constructor]
    pub fn from_hex_string(hex_string: &str) -> CoreCryptoResult<Self> {
        u64::from_str_radix(hex_string, 16)
            .map(Self)
            .map_err(|e| CoreCryptoError::Other {
                msg: format!("invalid device id: {e}"),
            })
    }

    /// Encode the `DeviceId` as a 16-character lowercase hex string, with leading 0s.
    pub fn to_hex_string(&self) -> String {
        format!("{:016x}", self.0)
    }

    /// Get the number corresponding to this `DeviceId`.
    pub fn to_u64(&self) -> u64 {
        self.0
    }
}
