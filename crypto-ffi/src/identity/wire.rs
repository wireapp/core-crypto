use wire_e2e_identity::legacy::device_status;

use crate::{CredentialType, X509Identity};

/// The identity claims identifying a client.
///
/// Those claims are verifiable by any member in the group.
#[derive(Debug, Clone, uniffi::Record)]
pub struct WireIdentity {
    /// Unique client identifier e.g. `T4Coy4vdRzianwfOgXpn6A:6add501bacd1d90e@whitehouse.gov`
    pub client_id: String,
    /// Status of the credential at the moment this object is created.
    pub status: DeviceStatus,
    /// MLS thumbprint
    pub thumbprint: String,
    /// Indicates whether the credential is Basic or X509.
    pub credential_type: CredentialType,
    /// The X509 certificate details; populated only when `credential_type` is X509.
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

/// The standalone status of a device credential in an MLS group at a given moment.
///
/// This does not represent states where a device is not using MLS or end-to-end identity.
#[derive(Debug, Copy, Clone, PartialEq, Eq, uniffi::Enum)]
#[repr(u8)]
pub enum DeviceStatus {
    /// The device credential is valid.
    Valid = 1,
    /// The device credential's certificate has expired.
    Expired = 2,
    /// The device credential's certificate has been revoked.
    ///
    /// Note: revocation is not yet implemented.
    Revoked = 3,
}

impl From<device_status::DeviceStatus> for DeviceStatus {
    fn from(value: device_status::DeviceStatus) -> Self {
        match value {
            device_status::DeviceStatus::Valid => Self::Valid,
            device_status::DeviceStatus::Expired => Self::Expired,
            device_status::DeviceStatus::Revoked => Self::Revoked,
        }
    }
}
