use crate::{CredentialType, X509Identity};

/// Represents the identity claims identifying a client
/// Those claims are verifiable by any member in the group
#[derive(Debug, Clone, uniffi::Record)]
pub struct WireIdentity {
    /// Unique client identifier e.g. `T4Coy4vdRzianwfOgXpn6A:6add501bacd1d90e@whitehouse.gov`
    pub client_id: String,
    /// Status of the Credential at the moment this object is created
    pub status: DeviceStatus,
    /// MLS thumbprint
    pub thumbprint: String,
    /// Indicates whether the credential is Basic or X509
    pub credential_type: CredentialType,
    /// In case 'credential_type' is [CredentialType::X509] this is populated
    pub x509_identity: Option<X509Identity>,
}

impl From<core_crypto::WireIdentity> for WireIdentity {
    fn from(i: core_crypto::WireIdentity) -> Self {
        Self {
            client_id: i.client_id,
            status: i.status.into(),
            thumbprint: i.thumbprint,
            credential_type: i.credential_type.into(),
            x509_identity: i.x509_identity.map(Into::into),
        }
    }
}

/// Indicates the standalone status of a device Credential in a MLS group at a moment T.
///
/// This does not represent the states where a device is not using MLS or is not using end-to-end identity
#[derive(Debug, Copy, Clone, PartialEq, Eq, uniffi::Enum)]
#[repr(u8)]
pub enum DeviceStatus {
    /// All is fine
    Valid = 1,
    /// The Credential's certificate is expired
    Expired = 2,
    /// The Credential's certificate is revoked (not implemented yet)
    Revoked = 3,
}

impl From<core_crypto::DeviceStatus> for DeviceStatus {
    fn from(value: core_crypto::DeviceStatus) -> Self {
        match value {
            core_crypto::DeviceStatus::Valid => Self::Valid,
            core_crypto::DeviceStatus::Expired => Self::Expired,
            core_crypto::DeviceStatus::Revoked => Self::Revoked,
        }
    }
}
