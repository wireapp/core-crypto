mod targeted;

use tls_codec::{TlsDeserialize, TlsSerialize, TlsSize};

/// The version of the Transient and Targeted Messages protocol.
#[derive(TlsSize, TlsSerialize, TlsDeserialize)]
#[repr(transparent)]
pub struct TransientAndTargetedMessagesProtocolVersion(u16);

impl TransientAndTargetedMessagesProtocolVersion {
    /// Transient and Targeted Messages Version 1
    pub const V1: Self = Self(1);
}
