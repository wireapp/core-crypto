pub(super) mod sender_nonce;
mod targeted;

use openmls::prelude::Signature;
use tls_codec::{Serialize, TlsDeserialize, TlsSerialize, TlsSize};

pub use crate::mls::core_crypto_message::targeted::{PskId, TargetedMessage, TargetedMessageContext};

/// The version of the Transient and Targeted Messages protocol.
#[derive(TlsSize, TlsSerialize, TlsDeserialize)]
#[repr(transparent)]
pub struct TransientAndTargetedMessagesProtocolVersion(u16);

impl TransientAndTargetedMessagesProtocolVersion {
    /// Transient and Targeted Messages Version 1
    pub const V1: Self = Self(1);
}

/// The body of [CoreCryptoMessageTBS], with currently three variants. The wire format is encoded in the leading two
/// bytes of the TLS-serialized version of this struct. The wire-format values are contained in the range reserved for
/// private use in RFC 9420.
#[derive(TlsSize, TlsSerialize, TlsDeserialize)]
#[repr(u16)]
#[non_exhaustive]
pub enum CoreCryptoMessageBody {
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

/// The to-be-signed [CoreCryptoMessage].
#[derive(TlsSize, TlsSerialize, TlsDeserialize)]
pub struct CoreCryptoMessageTBS {
    protocol_version: TransientAndTargetedMessagesProtocolVersion,
    body: CoreCryptoMessageBody,
}

impl CoreCryptoMessageTBS {
    #[expect(dead_code)]
    pub(crate) fn new_transient(transient: ()) -> Self {
        Self {
            protocol_version: TransientAndTargetedMessagesProtocolVersion::V1,
            body: CoreCryptoMessageBody::Transient(transient),
        }
    }

    pub(crate) fn new_targeted(targeted: TargetedMessage) -> Self {
        Self {
            protocol_version: TransientAndTargetedMessagesProtocolVersion::V1,
            body: CoreCryptoMessageBody::Targeted(targeted),
        }
    }

    pub(crate) fn new_transient_targeted(targeted: TargetedMessage) -> Self {
        Self {
            protocol_version: TransientAndTargetedMessagesProtocolVersion::V1,
            body: CoreCryptoMessageBody::TransientTargeted(targeted),
        }
    }
}

/// A message containing [CoreCryptoMessageBody] with the corresponding signature.
#[derive(TlsSize, TlsSerialize, TlsDeserialize)]
pub struct CoreCryptoMessage {
    content: CoreCryptoMessageTBS,
    signature: Signature,
}

impl CoreCryptoMessage {
    #[cfg(debug_assertions)]
    pub(crate) fn body(&self) -> &CoreCryptoMessageBody {
        &self.content.body
    }
}

impl openmls::prelude::Signable for CoreCryptoMessageTBS {
    type SignedOutput = CoreCryptoMessage;

    fn unsigned_payload(&self) -> Result<Vec<u8>, tls_codec::Error> {
        self.tls_serialize_detached()
    }

    fn label(&self) -> &str {
        match self.body {
            CoreCryptoMessageBody::Transient(_) => todo!(),
            CoreCryptoMessageBody::Targeted(_) => TargetedMessage::SIGN_LABEL_PERSISTED,
            CoreCryptoMessageBody::TransientTargeted(_) => TargetedMessage::SIGN_LABEL_TRANSIENT,
        }
    }
}

impl openmls::prelude::SignedStruct<CoreCryptoMessageTBS> for CoreCryptoMessage {
    fn from_payload(payload: CoreCryptoMessageTBS, signature: openmls::prelude::Signature) -> Self {
        Self {
            content: payload,
            signature,
        }
    }
}
