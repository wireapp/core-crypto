use log::info;
use obfuscate::Obfuscated;
use openmls::group::QueuedProposal;

use crate::{
    DecryptedMessage, DecryptionOutcome, Proposal, RecursiveError, WireIdentity,
    error::infrastructure::Infrastructural as _,
    mls::conversation::{ConversationMut, Error, Result, mutable::decrypt::RecursionPolicy},
};

/// Handle decryption of a proposal message.
pub(in crate::mls::conversation::mutable::decrypt) async fn handle(
    conversation: &mut ConversationMut,
    proposal: QueuedProposal,
    identity: WireIdentity,
    recursion_policy: RecursionPolicy,
) -> Result<DecryptedMessage> {
    conversation
        .mutate_group(async |_, group, id| {
            info!(
                group_id = id.to_owned(),
                sender = Obfuscated::from(proposal.sender()),
                proposals = Obfuscated::from(&proposal.proposal);
                "Received proposal"
            );
            group.store_pending_proposal(proposal);
            Ok(())
        })
        .await?;

    // Using a savepoint here means that a partially-applied commit doesn't affect the DB, in case
    // of an error.
    // We use a custom outcome check to ensure that the savepoint is only considered successful if
    // the outcome is a decrypted message. This ensures that i.e. a buffered commit which doesn't end up
    // applied is restored to the DB.
    let process_result = conversation
        .tx_context
        .inner()
        .map_err(RecursiveError::context(
            "getting tx context for savepoint for processing buffered commit",
        ))?
        .with_savepoint_with_outcome_check(
            "try_process_buffered_commit",
            async || -> Result<Option<_>> {
                let Some(commit_message) =
                    conversation
                        .take_buffered_commit()
                        .await
                        .map_err(RecursiveError::context(
                            "retrieving buffered commit while handling proposal",
                        ))?
                else {
                    return Ok(None);
                };

                let decryption_outcome = conversation
                    .try_process_buffered_commit(&commit_message.message, recursion_policy)
                    .await?;

                Ok(Some(decryption_outcome))
            },
            Error::savepoint,
            DecryptionOutcome::savepoint_outcome_check,
        )
        .await;

    if let Some(process_result) = process_result.transpose() {
        match process_result {
            Ok(DecryptionOutcome::Decrypted(decrypted)) => {
                // a successfully-processed buffered commit overrides the proposal's return value
                return Ok(decrypted);
            }
            Ok(DecryptionOutcome::Deferred(_)) => {
                // this is fine and we don't need error handling;
                // fall through to returning the proposal
            }
            Err(err) if err.is_infrastructure() => {
                // propagation means the outer transaction probably gets rolled back, meaning
                // that the client will eventually retry this proposal, which might succeed next time.
                // Also in the event that the error was something like the keystore being out of space,
                // this lets the client actually handle that appropriately.
                return Err(err);
            }
            Err(err) => {
                // all other errors get the same handling:
                //
                // 1. log the error (because some visibility is nice)
                // 2. clear the buffered commit (because future attempts would probably run into the same error, and the
                //    savepoint's failure restored it)
                // 3. fall through to successfully return the `DecryptedMessage::Proposal` variant
                //
                // This is correct because we have in fact correctly stored the pending proposal already,
                // and can't do anything about the error. If they propagated, a caller has only two options:
                //
                // - let the error propagate, which rolls back everything and will fail in the same way next time
                // - catch the error, which they can't do anything about but is now mandatory

                log::warn!(err:err; "failed to process buffered commit on receipt of a proposal");

                // In the future we could write a more optimized implementation, but this will get the job done for now
                conversation
                    .take_buffered_commit()
                    .await
                    .map_err(RecursiveError::context(
                        "clearing buffered commit after failed application",
                    ))?;
            }
        }
    }

    let delay = conversation.compute_next_commit_delay().await;

    Ok(DecryptedMessage::Proposal(Proposal { delay, identity }))
}
