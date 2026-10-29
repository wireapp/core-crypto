use log::info;
use obfuscate::Obfuscated;
use openmls::group::QueuedProposal;

use crate::{
    DecryptedMessage, Proposal, RecursiveError, WireIdentity,
    mls::conversation::{Conversation, ConversationMut, Error, Result, mutable::decrypt::RecursionPolicy},
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

    if let Some(commit) = conversation
        .retrieve_buffered_commit()
        .await
        .map_err(RecursiveError::context(
            "retrieving buffered commit while handling proposal",
        ))?
    {
        // using a savepoint here means that a partially-applied commit doesn't affect the DB, in case
        // of an error.
        let process_result = conversation
            .tx_context
            .inner()
            .map_err(RecursiveError::context(
                "getting tx context for savepoint for processing buffered commit",
            ))?
            .with_savepoint(
                "try_process_buffered_commit",
                async || {
                    conversation.clear_buffered_commit()?;
                    conversation.try_process_buffered_commit(commit, recursion_policy).await
                },
                Error::savepoint,
            )
            .await;

        match process_result {
            Ok(_) => {
                // a successfully-processed buffered commit overrides the proposal's return value
                return process_result;
            }
            Err(Error::BufferedCommit) => {
                // this is fine and we don't need error handling;
                // fall through to returning the proposal
            }
            Err(Error::Keystore(_)) => {
                // propagation means the outer transaction probably gets rolled back, meaning
                // that the client will eventually retry this proposal, which might succeed next time.
                // Also in the event that the error was something like the keystore being out of space,
                // this lets the client actually handle that appropriately.
                return process_result;
            }
            Err(Error::Recursive(RecursiveError::TransactionContext { ref source, .. }))
                if matches!(&**source, crate::transaction_context::Error::InvalidTransactionContext) =>
            {
                // in this case we also propagate because the transaction itself is gone
                return process_result;
            }
            Err(err) => {
                // all other errors get the same handling:
                //
                // 1. log the error (because some visibility is nice)
                // 2. reload this conversation from the DB (because try_process_buffered_commit probably altered state
                //    somehow)
                // 3. clear the buffered commit (because future attempts would probably run into the same error, and the
                //    savepoint's failure restored it)
                // 4. fall through to successfully return the `DecryptedMessage::Proposal` variant
                //
                // This is correct because we have in fact correctly stored the pending proposal already,
                // and can't do anything about the error. If they propagated, a caller has only two options:
                //
                // - let the error propagate, which rolls back everything and will fail in the same way next time
                // - catch the error, which they can't do anything about but is now mandatory

                log::warn!(err:err; "failed to process buffered commit on receipt of a proposal");

                {
                    let session = conversation.inner.session()?;
                    let mut cache = session.conversation_cache.lock().await;
                    cache.remove(&conversation.id);
                    let from_db = Conversation::load(&session, conversation.id.as_ref()).await?.ok_or(
                        Error::MlsGroupInvalidState(
                            "conversation vanished while reloading after a failed buffered commit",
                        ),
                    )?;
                    *conversation.inner.group.write().await = from_db.group.into_inner();
                }

                conversation.clear_buffered_commit().map_err(RecursiveError::context(
                    "clearing buffered commit after failed application",
                ))?;
            }
        }
    }

    let delay = conversation.compute_next_commit_delay().await;

    Ok(DecryptedMessage::Proposal(Proposal { delay, identity }))
}
