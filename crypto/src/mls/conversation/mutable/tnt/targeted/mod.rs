pub(super) mod encrypt;

use const_format::concatcp;
use derive_more::Constructor;
use openmls::{
    group::{GroupEpoch, GroupId, MlsGroup, group_context::GroupContext},
    prelude::{Ciphersuite, HpkeCiphertext, LeafNodeIndex},
};
use openmls_traits::OpenMlsCryptoProvider;
use tls_codec::{Serialize as _, TlsDeserialize, TlsSerialize, TlsSize};

use self::encrypt::TargetedMessagePolicy;
use super::{Error, ProtocolVersion, Result, tnt_message_counter::TntMessageCounter};
use crate::{ConversationConfiguration, OpenMlsError};

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
    fn new(
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
    nonce: TntMessageCounter,
    sender: LeafNodeIndex,
    recipient: LeafNodeIndex,
    epoch: GroupEpoch,
    group_id: GroupId,
    /// Encrypted with the receipient's HPKE public key; authenticated with a PSK derived from the epoch secret,
    /// guaranteeing that the sender was a member of the group during the epoch. An additional authentication layer is
    /// provided by the signature over the entire message. Before encryption, the HPKE plaintext is padded.
    payload: HpkeCiphertext,
}

impl TargetedMessage {
    pub(super) const PADDING_SIZE: usize = ConversationConfiguration::PADDING_SIZE;
    pub(super) const SIGN_LABEL_PERSISTED: &str =
        concatcp!("TntMessageTBS-Persisted-Targeted v", ProtocolVersion::V1.as_u16());
    pub(super) const SIGN_LABEL_TRANSIENT: &str =
        concatcp!("TntMessageTBS-Transient-Targeted v", ProtocolVersion::V1.as_u16());
    pub(super) const PSK_LABEL: &str = concatcp!("Tnt TargetedMessage Psk v", ProtocolVersion::V1.as_u16());
}

/// The data that is extracted from the MLS group when encrypting or decrypting a targeted message.
struct HpkeContextData {
    info: Vec<u8>,
    psk_id: Vec<u8>,
    psk: Vec<u8>,
}

fn extract_hpke_context_data(
    crypto_provider: &impl OpenMlsCryptoProvider,
    cipher_suite: &Ciphersuite,
    context: &TargetedMessageContext,
    mls_group: &MlsGroup,
) -> Result<HpkeContextData> {
    let info = context
        .tls_serialize_detached()
        .map_err(Error::tls_serialize("TargetedMessageContext"))?;

    // We can use an empty context because we're using a unique label.
    let psk = mls_group
        .export_secret(
            crypto_provider,
            TargetedMessage::PSK_LABEL,
            &[],
            cipher_suite.hash_length(),
        )
        .map_err(OpenMlsError::wrap("exporting targeted message psk"))?;
    let psk_id = PskId::new(mls_group.group_id().clone(), mls_group.epoch());
    let psk_id = psk_id.tls_serialize_detached().map_err(Error::tls_serialize("PskId"))?;

    Ok(HpkeContextData { info, psk_id, psk })
}
