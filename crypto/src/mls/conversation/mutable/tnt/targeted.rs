use derive_more::Constructor;
use openmls::{
    group::{GroupEpoch, GroupId, group_context::GroupContext},
    prelude::{HpkeCiphertext, LeafNodeIndex},
};
use tls_codec::{TlsDeserialize, TlsSerialize, TlsSize};

use super::{ProtocolVersion, sender_nonce::SenderNonce};
use crate::{ConversationConfiguration, mls::conversation::mutable::tnt::encrypt_targeted::TargetedMessagePolicy};

/// Used to parameterize HPKE Seal/Open.
/// Not carried with the payload, constructed freshly when decrypting.
#[derive(TlsSize, TlsSerialize)]
pub(super) struct TargetedMessageContext {
    protocol_version: ProtocolVersion,
    policy: TargetedMessagePolicy,
    sender: LeafNodeIndex,
    recipient: LeafNodeIndex,
    group_context: GroupContext,
}

impl TargetedMessageContext {
    pub(super) fn new(
        policy: TargetedMessagePolicy,
        group_context: &GroupContext,
        sender: LeafNodeIndex,
        recipient: LeafNodeIndex,
    ) -> Self {
        Self {
            policy,
            protocol_version: ProtocolVersion::V1,
            sender,
            recipient,
            group_context: group_context.clone(),
        }
    }
}

/// Used to parametrize HPKE Seal/Open
#[derive(Constructor, TlsSize, TlsSerialize)]
pub(super) struct PskId {
    group_id: GroupId,
    epoch: GroupEpoch,
}

/// Targeted messages are messages distributed to individual clients. They don't mutate regular group state (i.e, as
/// defined by RFC 9420). That is because many or most clients in a group will never receive those messages, and will
/// not have the appropriate cryptographic state to decrypt the messages.
///
/// Any feature using a targeted, transient or transient targeted message MUST specify why the lower security
/// guarantees (compared to MLS application messages) are acceptable and/or how they are mitigated.
///
/// Implementation note: we're preferring OpenMLS types here, because we're using OpenMLS encoding. Once we switch to
/// mls-rs, we're going to use mls-rs types.
#[derive(TlsSize, TlsSerialize, TlsDeserialize, Constructor)]
pub(super) struct TargetedMessage {
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
    pub(super) const PADDING_SIZE: usize = ConversationConfiguration::PADDING_SIZE;
    pub(super) const SIGN_LABEL_PERSISTED: &str = "CoreCryptoMessageTBS-Persisted-Targeted";
    pub(super) const SIGN_LABEL_TRANSIENT: &str = "CoreCryptoMessageTBS-Transient-Targeted";
    pub(super) const PSK_LABEL: &str = "CoreCrypto TargetedMessage Psk";
}
