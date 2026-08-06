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

/// The body of [TntMessageTBS], with currently three variants. The wire format is encoded in the leading two
/// bytes of the TLS-serialized version of this struct. The wire-format values are contained in the range reserved for
/// private use in RFC 9420.
#[derive(TlsSize, TlsSerialize, TlsDeserialize)]
#[repr(u16)]
#[non_exhaustive]
enum TntMessageBody {
    /// A transient message.
    #[tls_codec(discriminant = 0xF000)]
    Transient(()),
    /// A targeted message.
    #[tls_codec(discriminant = 0xF001)]
    Targeted(TargetedMessage),
    /// A transient, targeted message.
    #[tls_codec(discriminant = 0xF002)]
    TransientTargeted(TargetedMessage),
}

/// The to-be-signed [TntMessage].
#[derive(TlsSize, TlsSerialize, TlsDeserialize)]
struct TntMessageTBS {
    protocol_version: ProtocolVersion,
    body: TntMessageBody,
}

impl TntMessageTBS {
    #[expect(dead_code)]
    pub(crate) fn new_transient(transient: ()) -> Self {
        Self {
            protocol_version: ProtocolVersion::V1,
            body: TntMessageBody::Transient(transient),
        }
    }

    pub(crate) fn new_targeted(targeted: TargetedMessage) -> Self {
        Self {
            protocol_version: ProtocolVersion::V1,
            body: TntMessageBody::Targeted(targeted),
        }
    }

    pub(crate) fn new_transient_targeted(targeted: TargetedMessage) -> Self {
        Self {
            protocol_version: ProtocolVersion::V1,
            body: TntMessageBody::TransientTargeted(targeted),
        }
    }
}

/// A message containing [TntMessageBody] with the corresponding signature.
#[derive(TlsSize, TlsSerialize, TlsDeserialize)]
struct TntMessage {
    content: TntMessageTBS,
    signature: Signature,
}

impl openmls::prelude::Signable for TntMessageTBS {
    type SignedOutput = TntMessage;

    fn unsigned_payload(&self) -> Result<Vec<u8>, tls_codec::Error> {
        self.tls_serialize_detached()
    }

    fn label(&self) -> &str {
        match self.body {
            TntMessageBody::Transient(_) => todo!(),
            TntMessageBody::Targeted(_) => TargetedMessage::SIGN_LABEL_PERSISTED,
            TntMessageBody::TransientTargeted(_) => TargetedMessage::SIGN_LABEL_TRANSIENT,
        }
    }
}

impl openmls::prelude::SignedStruct<TntMessageTBS> for TntMessage {
    fn from_payload(payload: TntMessageTBS, signature: openmls::prelude::Signature) -> Self {
        Self {
            content: payload,
            signature,
        }
    }
}
