use derive_more::Constructor;
use openmls::{
    group::{GroupEpoch, GroupId, group_context::GroupContext},
    prelude::{HpkeCiphertext, LeafNodeIndex},
};
use tls_codec::{TlsDeserialize, TlsSerialize, TlsSize};

use crate::{
    ConversationConfiguration,
    mls::{SenderNonce, core_crypto_message::TransientAndTargetedMessagesProtocolVersion},
};

/// Used to parameterize HPKE Seal/Open.
/// Not carried with the payload, constructed freshly when decrypting.
#[derive(TlsSize, TlsSerialize, TlsDeserialize)]
pub struct TargetedMessageContext {
    protocol_version: TransientAndTargetedMessagesProtocolVersion,
    group_context: GroupContext,
}

impl TargetedMessageContext {
    pub(crate) fn new(group_context: &GroupContext) -> Self {
        Self {
            protocol_version: TransientAndTargetedMessagesProtocolVersion::V1,
            group_context: group_context.clone(),
        }
    }
}

impl TargetedMessageContext {
    /// The label used when encrypting a Targeted Message.
    pub const ENCRYPTION_LABEL: &str = "CoreCrypto TargetedMessageContext";
}

/// Used to parametrize HPKE Seal/Open
#[derive(Constructor, TlsSize, TlsSerialize)]
pub struct PskId {
    group_id: GroupId,
    epoch: GroupEpoch,
}

/// Targeted messages are messages distributed to individual clients. They cannot mutate group state because many or
/// most clients in a group will never receive those messages, and will not have the appropriate cryptographic state to
/// decrypt the messages.
///
/// Any feature using a targeted, transient or transient targeted message MUST specify why the compared to MLS
/// application messages lower guarantees are acceptable and/or how they are mitigated.
///
/// Implementation note: we're preferring OpenMLS types here, because we're using OpenMLS encoding. Once we switch to
/// mls-rs, we're going to use mls-rs types.
#[derive(TlsSize, TlsSerialize, TlsDeserialize, Constructor)]
pub struct TargetedMessage {
    nonce: SenderNonce,
    sender: LeafNodeIndex,
    recipient: LeafNodeIndex,
    epoch: GroupEpoch,
    group_id: GroupId,
    /// Ecrypted with the receipient's HPKE public key; authenticated with epoch secret as PSK.
    /// The encrypted payload will typically be GenericMessage protobuf.
    /// Must have padding like the openmls ciphertexts.
    payload: HpkeCiphertext,
}

impl TargetedMessage {
    const PADDING_SIZE: usize = ConversationConfiguration::PADDING_SIZE;
    pub(super) const SIGN_LABEL_PERISTED: &str = "CoreCryptoMessageTBS-Persisted-Targeted";
    pub(super) const SIGN_LABEL_TRANSIENT: &str = "CoreCryptoMessageTBS-Transient-Targeted";
    pub(crate) const PSK_LABEL: &str = "CoreCrypto TargetedMessage Psk";
}
