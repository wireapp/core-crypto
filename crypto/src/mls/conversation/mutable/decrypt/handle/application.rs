use log::debug;
use openmls::{group::GroupEpoch, prelude::ApplicationMessage};

use crate::{
    ClientId, DecryptedBytes, DecryptedMessage, RecursiveError, WireIdentity,
    mls::conversation::{ConversationMut, Result},
};

/// Handle decryption of an application message.
pub(in crate::mls::conversation::mutable::decrypt) fn handle(
    conversation: &ConversationMut,
    application_message: ApplicationMessage,
    epoch: GroupEpoch,
    identity: WireIdentity,
    sender_client_id_result: Result<ClientId, RecursiveError>,
) -> Result<DecryptedMessage> {
    let sender_client_id = sender_client_id_result?;
    debug!(
        group_id = conversation.id().to_owned(),
        epoch = epoch.as_u64(),
        sender_client_id = sender_client_id;
        "Application message"
    );

    Ok(DecryptedMessage::ApplicationMessage(DecryptedBytes {
        plaintext: application_message.into_bytes(),
        sender_client_id,
        identity,
    }))
}
