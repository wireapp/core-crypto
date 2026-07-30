//! Targeted Messages. TODO(SimonThormeyer) add proper module docs

use openmls::{
    group::{GroupEpoch, GroupId, group_context::GroupContext},
    prelude::{HpkeCiphertext, LeafNodeIndex},
};
use tls_codec::{TlsDeserialize, TlsSerialize, TlsSize};

use crate::{
    ConversationConfiguration,
    mls::{CoreCryptoWireFormat, TransientAndTargetedMessageNonce, TransientAndTargetedMessagesProtocolVersion},
};

/// Used to parameterize HPKE Seal/Open.
/// Not carried with the payload, constructed freshly when decrypting.
#[derive(TlsSize, TlsSerialize, TlsDeserialize)]
pub struct TargetedMessageContext {
    protocol_version: TransientAndTargetedMessagesProtocolVersion,
    group_context: GroupContext,
}

impl TargetedMessageContext {
    /// The label used when encrypting a Targeted Message.
    pub const ENCRYPTION_LABEL: &str = "CoreCrypto TargetedMessageContext";
}

/// Used to parametrize HPKE Seal/Open
#[derive(TlsSize, TlsSerialize)]
pub struct PskId {
    group_id: GroupId,
    epoch: GroupEpoch,
}

impl PskId {
    /// TODO(SimonThormeyer) Do we need this label?
    pub const LABEL: &str = "CoreCrypto PskId";
}

/// To-be-signed [TargetedMessage].
#[derive(TlsSize, TlsSerialize, TlsDeserialize)]
pub struct TargetedMessageTBS {
    protocol_version: TransientAndTargetedMessagesProtocolVersion,
    wire_format: CoreCryptoWireFormat,
    nonce: TransientAndTargetedMessageNonce,
    sender: LeafNodeIndex,
    recipient: LeafNodeIndex,
    epoch: GroupEpoch,
    group_id: GroupId,
    /// Ecrypted with the receipient's HPKE public key; authenticated with epoch secret as PSK.
    /// The encrypted payload will typically be GenericMessage protobuf.
    /// Must have padding like the openmls ciphertexts.
    payload: HpkeCiphertext,
}

/// Targeted messages are messages distributed to individual clients. They cannot mutate group state because many or
/// most clients in a group will never receive those messages, and will not have the appropriate cryptographic state to
/// decrypt the messages.
///
/// Any feature using a targeted, transient or transient targeted message MUST specify why the compared to MLS
/// application messages lower guarantees are acceptable and/or how they are mitigated.
#[derive(TlsSize, TlsSerialize, TlsDeserialize)]
pub struct TargetedMessage {
    inner: TargetedMessageTBS,
    signature: Vec<u8>, // signs the serialization of the `inner` struct
}

impl TargetedMessage {
    const PADDING_SIZE: usize = ConversationConfiguration::PADDING_SIZE;
}
