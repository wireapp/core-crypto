use log::info;
use obfuscate::Obfuscated;
use openmls::group::StagedCommit;

use crate::{
    BufferedDecryptedMessage, Commit, DecryptedMessage, OpenMlsError, RecursiveError, WireIdentity,
    mls::conversation::{ConversationMut, Result, mutable::decrypt::RecursionPolicy},
};

/// Handle decryption of staged commit message.
pub(in crate::mls::conversation::mutable::decrypt) async fn handle(
    conversation: &mut ConversationMut,
    staged_commit: StagedCommit,
    identity: WireIdentity,
    recursion_policy: RecursionPolicy,
) -> Result<DecryptedMessage> {
    conversation.validate_commit(&staged_commit).await?;
    let provider = conversation.crypto_provider().await?;

    let (mut is_active, removed_members, added_members, group_id) = conversation
        .mutate_group(async |_, group, id| {
            let removed_indices = staged_commit
                .remove_proposals()
                .map(|p| p.remove_proposal().removed())
                .collect::<Vec<_>>();

            let added_credentials = staged_commit
                .add_proposals()
                .map(|p| p.add_proposal().key_package.leaf_node().credential().to_owned())
                .collect::<Vec<_>>();

            let removed_members = ConversationMut::members_at_indices(removed_indices, group);

            group
                .merge_staged_commit(&provider, staged_commit.clone())
                .await
                .map_err(OpenMlsError::wrap("merge staged commit"))?;

            let added_members = group
                .members()
                .filter_map(|member| added_credentials.contains(&member.credential).then(|| member.clone()))
                .collect::<Vec<_>>();

            let is_active = group.is_active();
            let group_id = id.to_owned();

            Ok((is_active, removed_members, added_members, group_id))
        })
        .await?;

    // can't use `.then` because async
    let mut buffered_messages = None;
    if is_active && recursion_policy == RecursionPolicy::AsNecessary {
        buffered_messages = conversation.restore_and_clear_pending_messages().await?;

        // ensure that if any buffered message evicts us from the group, we propagate that info
        if let Some(buffered_messages) = buffered_messages.as_ref() {
            for message in buffered_messages {
                if let BufferedDecryptedMessage::Commit(commit) = message {
                    is_active &= commit.is_active;
                    if !is_active {
                        break;
                    }
                }
            }
        }
    }

    let epoch = staged_commit.staged_context().epoch().as_u64();
    info!(
        added = Obfuscated::from(&added_members),
        removed = Obfuscated::from(&removed_members),
        group_id,
        epoch,
        proposals:? = staged_commit.queued_proposals().map(Obfuscated::from).collect::<Vec<_>>();
        "Epoch advanced"
    );
    conversation
        .tx_context
        .queue_epoch_changed(group_id, epoch)
        .await
        .map_err(RecursiveError::context("queueing epoch changed notification"))?;

    Ok(DecryptedMessage::Commit(Commit {
        is_active,
        buffered_messages,
        identity,
    }))
}
