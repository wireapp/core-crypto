mod targeted;

use openmls::prelude::Signature;
use tls_codec::{Serialize, TlsDeserialize, TlsSerialize, TlsSize};

pub(crate) use self::sender_nonce::SenderNonce;
use self::targeted::{PskId, TargetedMessage, TargetedMessageContext};

/// The version of the Transient and Targeted Messages protocol.
#[derive(TlsSize, TlsSerialize, TlsDeserialize)]
#[repr(transparent)]
struct ProtocolVersion(u16);

impl ProtocolVersion {
    /// Transient and Targeted Messages Version 1
    pub(crate) const V1: Self = Self(1);
}
