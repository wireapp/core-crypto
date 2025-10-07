use std::time::{Duration, SystemTime};

/// Represents the parts of [WireIdentity][crate::WireIdentity] that are specific to a X509 certificate (and not a Basic one).
///
/// We don't use an enum here since the sole purpose of this is to be exposed through the FFI (and
/// union types are impossible to carry over the FFI boundary)
#[derive(Debug, Clone, uniffi::Record)]
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

    /// X509 certificate not before
    pub not_before: SystemTime,

    /// X509 certificate not after
    pub not_after: SystemTime,
}

impl From<core_crypto::X509Identity> for X509Identity {
    fn from(i: core_crypto::X509Identity) -> Self {
        let not_before = SystemTime::UNIX_EPOCH + Duration::from_secs(i.not_before);

        let not_after = SystemTime::UNIX_EPOCH + Duration::from_secs(i.not_after);

        Self {
            handle: i.handle,
            display_name: i.display_name,
            domain: i.domain,
            certificate: i.certificate,
            serial_number: i.serial_number,
            not_before,
            not_after,
        }
    }
}
