use crate::Timestamp;

/// Fields from a `WireIdentity` that are specific to X509 credentials.
#[derive(Debug, Clone, uniffi::Record)]
pub struct X509Identity {
    /// User handle e.g. `john_wire`
    pub handle: String,
    /// Name as displayed in the messaging application e.g. `John Fitzgerald Kennedy`
    pub display_name: String,
    /// DNS domain for which this identity proof was generated e.g. `whitehouse.gov`
    pub domain: String,
    /// PEM-encoded X509 certificate identifying this client in the MLS group.
    pub certificate: String,
    /// X509 certificate serial number
    pub serial_number: String,

    /// Certificate validity start time (the X509 notBefore field).
    pub not_before: Timestamp,

    /// Certificate validity end time (the X509 notAfter field).
    pub not_after: Timestamp,
}

impl From<core_crypto::X509Identity> for X509Identity {
    fn from(i: core_crypto::X509Identity) -> Self {
        Self {
            handle: i.handle,
            display_name: i.display_name,
            domain: i.domain,
            certificate: i.certificate,
            serial_number: i.serial_number,
            not_before: Timestamp::from_epoch_secs(i.not_before),
            not_after: Timestamp::from_epoch_secs(i.not_after),
        }
    }
}
