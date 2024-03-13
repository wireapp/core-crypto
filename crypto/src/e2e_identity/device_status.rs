use wire_e2e_identity::prelude::IdentityStatus;

/// Indicates the standalone status of a device Credential in a MLS group at a moment T.
/// This does not represent the states where a device is not using MLS or is not using end-to-end identity
#[derive(Debug, Clone, Copy, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[repr(u8)]
pub enum DeviceStatus {
    /// All is fine
    Valid = 1,
    /// The Credential's certificate is expired
    Expired = 2,
    /// The Credential's certificate is revoked
    Revoked = 3,
}

impl From<IdentityStatus> for DeviceStatus {
    fn from(status: IdentityStatus) -> Self {
        match status {
            IdentityStatus::Valid => Self::Valid,
            IdentityStatus::Expired => Self::Expired,
            IdentityStatus::Revoked => Self::Revoked,
        }
    }
}
