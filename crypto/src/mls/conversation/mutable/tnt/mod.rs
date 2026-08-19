mod targeted;
mod tnt_message_counter;

use openmls::prelude::{LeafNodeIndex, OpenMlsSignaturePublicKey, Signature, Verifiable as _};
use openmls_traits::OpenMlsCryptoProvider;
use tls_codec::{Serialize, TlsDeserialize, TlsSerialize, TlsSize};

use self::targeted::TargetedMessage;
pub use self::targeted::encrypt::TargetedMessagePolicy;
pub(crate) use self::tnt_message_counter::TntMessageCounter;
use super::Result;
use crate::{
    DecryptedMessage, OpenMlsError,
    mls::conversation::{ConversationMut, Error},
};

/// The version of the Transient and Targeted Messages protocol.
#[derive(TlsSize, TlsSerialize, TlsDeserialize)]
#[repr(transparent)]
struct ProtocolVersion(u16);

impl ProtocolVersion {
    /// Transient and Targeted Messages Version 1
    const V1: Self = Self(1);

    const fn as_u16(&self) -> u16 {
        self.0
    }
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

#[derive(TlsSize, TlsDeserialize)]
pub(crate) struct TntWireFormat(u16);

impl TntWireFormat {
    pub(crate) const TRANSIENT_MESSAGE: u16 = 0xF000;
    #[expect(unused)]
    pub(crate) const TARGETED_MESSAGE: u16 = 0xF001;
    pub(crate) const TRANSIENT_TARGETED_MESSAGE: u16 = 0xF002;

    pub(crate) fn all() -> std::ops::RangeInclusive<u16> {
        Self::TRANSIENT_MESSAGE..=Self::TRANSIENT_TARGETED_MESSAGE
    }
}

/// The to-be-signed [TntMessage].
#[derive(TlsSize, TlsSerialize, TlsDeserialize)]
struct TntMessageTBS {
    protocol_version: ProtocolVersion,
    body: TntMessageBody,
}

impl TntMessageTBS {
    #[expect(dead_code)]
    fn new_transient(transient: ()) -> Self {
        Self {
            protocol_version: ProtocolVersion::V1,
            body: TntMessageBody::Transient(transient),
        }
    }

    fn new_targeted(targeted: TargetedMessage) -> Self {
        Self {
            protocol_version: ProtocolVersion::V1,
            body: TntMessageBody::Targeted(targeted),
        }
    }

    fn new_transient_targeted(targeted: TargetedMessage) -> Self {
        Self {
            protocol_version: ProtocolVersion::V1,
            body: TntMessageBody::TransientTargeted(targeted),
        }
    }

    pub(super) fn sender_index(&self) -> LeafNodeIndex {
        match &self.body {
            TntMessageBody::Transient(_) => todo!(),
            TntMessageBody::Targeted(targeted_message) | TntMessageBody::TransientTargeted(targeted_message) => {
                targeted_message.sender()
            }
        }
    }
}

/// A message containing [TntMessageBody] with the corresponding signature.
#[derive(TlsSize, TlsSerialize, TlsDeserialize)]
pub(super) struct TntMessage {
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

impl openmls::prelude::Verifiable for TntMessage {
    fn unsigned_payload(&self) -> Result<Vec<u8>, tls_codec::Error> {
        self.content.tls_serialize_detached()
    }

    fn signature(&self) -> &Signature {
        &self.signature
    }

    fn label(&self) -> &str {
        match self.content.body {
            TntMessageBody::Transient(_) => todo!(),
            TntMessageBody::Targeted(_) => TargetedMessage::SIGN_LABEL_PERSISTED,
            TntMessageBody::TransientTargeted(_) => TargetedMessage::SIGN_LABEL_TRANSIENT,
        }
    }
}

impl ConversationMut {
    /// Verify the [TntMessage] signature, then proceed with decryption.
    pub(super) async fn decrypt_tnt_message(&self, message: TntMessage) -> Result<DecryptedMessage> {
        let crypto_provider = self.crypto_provider().await?;
        let signature_algorithm = self.cipher_suite().signature_algorithm();
        let sender = self
            .group()
            .await
            .members()
            .find(|member| member.index == message.content.sender_index())
            .ok_or(Error::MlsMessageInvalidState("tnt sender is not a group member"))?;

        let sender_public_key =
            OpenMlsSignaturePublicKey::new(sender.signature_key.clone().into(), signature_algorithm)
                .map_err(OpenMlsError::wrap("constructing tnt sender signature key"))?;
        message
            .verify_no_out(crypto_provider.crypto(), &sender_public_key)
            .map_err(OpenMlsError::wrap("verifying tnt message signature"))?;

        match message.content.body {
            TntMessageBody::Transient(_) => todo!(),
            TntMessageBody::Targeted(targeted_message) => {
                self.decrypt_targeted(targeted_message, TargetedMessagePolicy::Persisted, &sender)
                    .await
            }
            TntMessageBody::TransientTargeted(targeted_message) => {
                self.decrypt_targeted(targeted_message, TargetedMessagePolicy::Transient, &sender)
                    .await
            }
        }
    }
}
