use const_format::concatcp;
use openmls::{
    group::{GroupEpoch, MlsGroup, group_context::GroupContext},
    prelude::{LeafNodeIndex, OpenMlsCrypto as _},
};
use openmls_traits::OpenMlsCryptoProvider;
use tls_codec::{SecretVLBytes, Serialize as _, TlsDeserialize, TlsSerialize, TlsSize};

use super::{Error, Result};
use crate::{
    OpenMlsError, TlsCodecError,
    mls::{
        TntMessageCounter,
        conversation::mutable::tnt::{ProtocolVersion, TntWireFormat},
    },
};

/// Used as aad for AEAD.
#[derive(TlsSize, TlsDeserialize, TlsSerialize)]
struct TransientMessageAad {
    protocol_version: ProtocolVersion,
    wire_format: TntWireFormat,
    sender: LeafNodeIndex,
    counter: TntMessageCounter,
    /// The mls group context ([https://www.rfc-editor.org/info/rfc9420/#name-group-context]) contains the epoch and
    /// group id, so we don't need those in additional fields here.
    group_context: GroupContext,
}

impl TransientMessageAad {
    fn new(sender: LeafNodeIndex, counter: TntMessageCounter, group_context: &GroupContext) -> Self {
        Self {
            protocol_version: ProtocolVersion::CURRENT,
            wire_format: TntWireFormat::TRANSIENT_MESSAGE.into(),
            sender,
            counter,
            group_context: group_context.clone(),
        }
    }
}

/// Transient messages are messages distributed to clients with an active WebSocket connection. They don't mutate
/// regular group state (i.e., as defined by RFC 9420). That is because offline clients will never receive those
/// messages, and will not have the appropriate cryptographic state to decrypt the messages.
///
/// Any feature using a targeted, transient or transient targeted message MUST specify why the lower security guarantees
/// (compared to MLS application messages) are acceptable and/or how they are mitigated.
///
/// Implementation note: we're preferring OpenMLS types here, because we're using OpenMLS encoding. Once we switch to
/// mls-rs, we're going to use mls-rs types.
#[derive(TlsSize, TlsSerialize, TlsDeserialize, derive_more::Constructor)]
pub(super) struct TransientMessage {
    sender: LeafNodeIndex,
    counter: TntMessageCounter,
    /// The mls group context ([https://www.rfc-editor.org/info/rfc9420/#name-group-context]) contains the epoch and
    /// group id, so we don't need those in additional fields here.
    group_context: GroupContext,
    /// AEAD-encrypted with an MLS exporter secret. An additional authentication layer is
    /// provided by the signature over the entire message. Before encryption, the plaintext is padded.
    payload: Vec<u8>,
}

impl TransientMessage {
    pub(super) const SIGN_LABEL: &str = concatcp!("TntMessageTBS-Transient v", ProtocolVersion::CURRENT.as_u16());
    pub(super) const AEAD_SECRET_KEY_LABEL: &str =
        concatcp!("Tnt TransientMessage Secret Key v", ProtocolVersion::CURRENT.as_u16());
    pub(super) const AEAD_NONCE_SECRET_LABEL: &str =
        concatcp!("Tnt TransientMessage Nonce Secret v", ProtocolVersion::CURRENT.as_u16());

    fn aad(&self, protocol_version: ProtocolVersion) -> TransientMessageAad {
        TransientMessageAad {
            protocol_version,
            wire_format: TntWireFormat::TRANSIENT_MESSAGE.into(),
            sender: self.sender,
            counter: self.counter,
            group_context: self.group_context.clone(),
        }
    }

    fn epoch(&self) -> GroupEpoch {
        self.group_context.epoch()
    }

    pub(super) fn sender(&self) -> LeafNodeIndex {
        self.sender
    }
}
