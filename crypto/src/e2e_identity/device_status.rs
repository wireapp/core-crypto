use wire_e2e_identity::prelude::IdentityStatus;

/// Indicates the standalone status of a device Credential in a MLS group at a moment T.
/// This does not represent the states where a device is not using MLS or is not using end-to-end identity
#[derive(Debug, Clone, Copy, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[repr(u8)]
pub enum DeviceStatus {
    /// All is fine
    Valid,
    /// The Credential's certificate is expired
    Expired,
    /// The Credential's certificate is revoked (not implemented yet)
    Revoked,
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
