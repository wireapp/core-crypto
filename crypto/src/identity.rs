use wire_e2e_identity::legacy::device_status::DeviceStatus;
use x509_cert::der::pem::LineEnding;

use super::{Error, Result};
use crate::{ClientId, CredentialType, RecursiveError};

/// Represents the identity claims identifying a client
/// Those claims are verifiable by any member in the group
#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd)]
pub struct WireIdentity {
    /// Unique client identifier e.g. `T4Coy4vdRzianwfOgXpn6A:6add501bacd1d90e@whitehouse.gov`
    pub client_id: Option<ClientId>,
    /// MLS thumbprint
    pub thumbprint: String,
    /// Status of the Credential at the moment T when this object is created
    pub status: DeviceStatus,
    /// Indicates whether the credential is Basic or X509
    pub credential_type: CredentialType,
    /// In case 'credential_type' is [CredentialType::X509] this is populated
    pub x509_identity: Option<X509Identity>,
}

/// Represents the parts of [WireIdentity] that are specific to a X509 certificate (and not a Basic one).
///
/// We don't use an enum here since the sole purpose of this is to be exposed through the FFI (and
/// union types are impossible to carry over the FFI boundary)
#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd)]
pub struct X509Identity {
    /// user handle e.g. `john_wire`
    pub handle: String,
    /// Name as displayed in the messaging application e.g. `John Fitzgerald Kennedy`
    pub display_name: String,
    /// DNS domain for which this identity proof was generated e.g. `whitehouse.gov`
    pub domain: String,
    /// X509 certificate identifying this client in the MLS group ; PEM encoded
    pub certificate: String,
    /// X509 certificate serial number
    pub serial_number: String,
    /// X509 certificate not before as Unix timestamp
    pub not_before: u64,
    /// X509 certificate not after as Unix timestamp
    pub not_after: u64,
}

impl<'a> TryFrom<(wire_e2e_identity::WireIdentity, &'a [u8])> for WireIdentity {
    type Error = Error;

    fn try_from((e2ei_wire_identity, cert_bytes): (wire_e2e_identity::WireIdentity, &'a [u8])) -> Result<Self> {
        use x509_cert::der::Decode as _;
        let document = x509_cert::der::Document::from_der(cert_bytes)
            .map_err(wire_e2e_identity::E2eIdentityError::X509CertDerError)?;
        let certificate = document
            .to_pem("CERTIFICATE", LineEnding::LF)
            .map_err(wire_e2e_identity::E2eIdentityError::X509CertDerError)?;

        let client_id = ClientId::try_from_str_with_base64_user_id(&e2ei_wire_identity.client_id)
            .map(Some)
            .map_err(RecursiveError::mls_client("client id from qualified string"))?;

        Ok(Self {
            client_id,
            status: e2ei_wire_identity.status.into(),
            thumbprint: e2ei_wire_identity.thumbprint,
            credential_type: CredentialType::X509,
            x509_identity: Some(X509Identity {
                handle: e2ei_wire_identity.handle.to_string(),
                display_name: e2ei_wire_identity.display_name,
                domain: e2ei_wire_identity.domain,
                certificate,
                serial_number: e2ei_wire_identity.serial_number,
                not_before: e2ei_wire_identity.not_before,
                not_after: e2ei_wire_identity.not_after,
            }),
        })
    }
}
