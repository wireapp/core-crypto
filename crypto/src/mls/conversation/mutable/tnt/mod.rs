use tls_codec::{TlsDeserialize, TlsSerialize, TlsSize};

/// The version of the Transient and Targeted Messages protocol.
#[derive(TlsSize, TlsSerialize, TlsDeserialize)]
#[repr(transparent)]
struct ProtocolVersion(u16);

impl ProtocolVersion {
    /// Transient and Targeted Messages Version 1
    pub(crate) const V1: Self = Self(1);
}
