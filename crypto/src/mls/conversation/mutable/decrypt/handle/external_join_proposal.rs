use log::info;
use obfuscate::Obfuscated;
use openmls::group::QueuedProposal;

use crate::{
    DecryptedMessage, Proposal, WireIdentity,
    mls::conversation::{ConversationMut, Result},
};

/// Handle decryption of an external join proposal message.
pub(in crate::mls::conversation::mutable::decrypt) async fn handle(
    conversation: &mut ConversationMut,
    proposal: QueuedProposal,
    identity: WireIdentity,
) -> Result<DecryptedMessage> {
    conversation
        .mutate_group(async |_, group, id| {
            info!(
                group_id = id.to_owned(),
                sender = Obfuscated::from(proposal.sender());
                "Received external join proposal"
            );
            group.store_pending_proposal(proposal);
            Ok(())
        })
        .await?;

    let delay = conversation.compute_next_commit_delay().await;

    Ok(DecryptedMessage::Proposal(Proposal { delay, identity }))
}
