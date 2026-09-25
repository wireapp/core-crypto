use core_crypto_keystore::{
    entities::StoredBufferedCommit,
    traits::{EntityDatabaseMutation as _, EntityDeleteBorrowed, FetchFromDatabase as _},
};
use log::info;
use openmls::framing::MlsMessageIn;
use tls_codec::Deserialize as _;

use super::{ConversationMut, RecursionPolicy, Result};
use crate::{DecryptedMessage, KeystoreError, RecursiveError, TlsCodecError};

impl ConversationMut {
    /// Cache the bytes of a buffered commit in the backend.
    ///
    /// By storing the raw commit bytes and doing deserialization/decryption from scratch, we preserve all
    /// security guarantees. When we do restore, it's as though the commit had simply been received later.
    pub(super) fn buffer_commit(&self, commit: impl AsRef<[u8]>) -> Result<()> {
        info!(group_id = self.id().to_owned(); "buffering commit");

        let buffered_commit = StoredBufferedCommit::new(self.id().to_bytes(), commit.as_ref().to_owned());

        let context_inner = self.tx_context.inner().map_err(RecursiveError::context(
            "getting context inner for transaction for buffering commit",
        ))?;
        buffered_commit
            .save(context_inner.transaction())
            .map_err(KeystoreError::wrap("buffering commit"))?;

        Ok(())
    }

    /// Retrieve the bytes of a pending commit.
    pub(super) async fn retrieve_buffered_commit(&self) -> Result<Option<Vec<u8>>> {
        let database = self.database()?;
        info!(group_id = self.id().to_owned(); "attempting to retrieve buffered commit");
        database
            .get_borrowed::<StoredBufferedCommit>(self.id().as_ref())
            .await
            .map(|option| option.map(|commit| commit.commit_data().to_owned()))
            .map_err(KeystoreError::wrap("attempting to retrieve buffered commit"))
            .map_err(Into::into)
    }

    /// Try to apply a buffered commit.
    ///
    /// This is largely a convenience function which handles deserializing the message, and
    /// gives a convenient point around which we can add context to errors. However, it's also
    /// a place where we can introduce a pin, given that we're otherwise doing a recursive
    /// async call, which would result in an infinitely-sized future.
    pub(super) async fn try_process_buffered_commit(
        &mut self,
        commit: impl AsRef<[u8]>,
        recursion_policy: RecursionPolicy,
    ) -> Result<DecryptedMessage> {
        info!(group_id = self.id().to_owned(); "attempting to process buffered commit");

        let message = MlsMessageIn::tls_deserialize(&mut commit.as_ref())
            .map_err(TlsCodecError::deserialize("mls message in"))?;

        Box::pin(self.decrypt_mls_message(message, recursion_policy)).await
    }

    /// Remove the buffered commit for this conversation; it has been applied.
    pub(super) fn clear_buffered_commit(&self) -> Result<bool> {
        info!(group_id = self.id().to_owned(); "attempting to delete buffered commit");
        let context_inner = self.tx_context.inner().map_err(RecursiveError::context(
            "getting context inner for transaction for clearing buffered commit",
        ))?;
        StoredBufferedCommit::delete_borrowed(context_inner.transaction(), self.id().as_ref())
            .map_err(KeystoreError::wrap("attempting to clear buffered commit"))
            .map_err(Into::into)
    }
}

#[cfg(test)]
mod tests {
    use core_crypto_keystore::{entities::MlsPendingMessage, traits::EntityDatabaseMutation as _};

    use crate::{BufferedDecryptedMessage, DecryptedMessage, mls::conversation::Error, test_utils::*};

    /// Set up the common scenario for these tests: Alice has buffered Bob's commit, which removes
    /// Charlie, because it refers to a proposal she never received.
    ///
    /// Bob's commit is merged on his side, so he is at epoch 2 while Alice and Charlie are still at epoch 1.
    /// Returns the conversation and the serialized proposal Alice is missing.
    async fn alice_buffers_commit_missing_proposal<'a>(
        case: &'a TestContext,
        [alice, bob, charlie]: [&'a SessionContext; 3],
    ) -> (TestConversation<'a>, Vec<u8>) {
        let conversation = case.create_conversation([alice, bob, charlie]).await;

        let proposal_guard = conversation.acting_as(bob).await.remove_proposal(charlie).await;
        let missing_proposal = proposal_guard.message().to_bytes().unwrap();
        let conversation = proposal_guard.finish();

        let commit_guard = conversation.acting_as(bob).await.commit_pending_proposals().await;
        let (commit_guard, result) = commit_guard.notify_member_fallible(alice).await;
        assert!(matches!(result.unwrap_err(), Error::BufferedCommit));
        let conversation = commit_guard.finish();
        assert_eq!(
            alice.transaction.count_entities().await.buffered_commits,
            1,
            "the commit Alice could not apply must have been buffered"
        );

        (conversation, missing_proposal)
    }

    /// A proposal which doesn't complete the buffered commit must leave it buffered.
    ///
    /// Every incoming proposal retries the buffered commit. When the retry reports that proposals are
    /// still missing, the commit must stay where it is, so that it can apply once the proposal it is
    /// actually waiting for arrives. Discarding it instead would silently lose that epoch.
    #[apply(all_cred_cipher)]
    async fn unrelated_proposal_must_not_discard_buffered_commit(case: TestContext) {
        let [alice, bob, charlie] = case.sessions().await;
        let (conversation, missing_proposal) =
            alice_buffers_commit_missing_proposal(&case, [&alice, &bob, &charlie]).await;

        // Charlie, still at epoch 1, sends an unrelated proposal. Alice accepts it, but it doesn't
        // complete Bob's commit.
        let proposal_guard = conversation.acting_as(&charlie).await.remove_proposal(&bob).await;
        let (proposal_guard, result) = proposal_guard.notify_member_fallible(&alice).await;
        assert!(
            matches!(result, Ok(DecryptedMessage::Proposal(_))),
            "the unrelated proposal must decrypt as a proposal: {result:?}"
        );
        let conversation = proposal_guard.finish();
        assert_eq!(
            alice.transaction.count_entities().await.buffered_commits,
            1,
            "the commit is still missing a proposal, so it must still be buffered"
        );

        // The proposal Bob's commit is waiting for arrives, and the commit applies.
        let decrypted = conversation
            .guard_of(&alice)
            .await
            .decrypt_message(&missing_proposal)
            .await
            .unwrap();
        assert!(
            decrypted.as_commit().is_some(),
            "the missing proposal must apply the buffered commit"
        );
    }

    /// A buffered commit which applies must be removed from the buffer.
    ///
    /// Otherwise the next proposal retries a commit which is already part of the group's history.
    #[apply(all_cred_cipher)]
    async fn applied_buffered_commit_must_be_unbuffered(case: TestContext) {
        let [alice, bob, charlie] = case.sessions().await;
        let (conversation, missing_proposal) =
            alice_buffers_commit_missing_proposal(&case, [&alice, &bob, &charlie]).await;

        let decrypted = conversation
            .guard_of(&alice)
            .await
            .decrypt_message(&missing_proposal)
            .await
            .unwrap();
        assert!(
            decrypted.as_commit().is_some(),
            "the missing proposal must apply the buffered commit"
        );
        assert_eq!(
            alice.transaction.count_entities().await.buffered_commits,
            0,
            "the buffered commit has applied, so it must no longer be buffered"
        );
    }

    /// Applying a buffered commit must not retry that same commit while it is being applied.
    ///
    /// Once the buffered commit merges, the messages buffered for the new epoch are replayed. If one of
    /// them is a proposal, it retries whatever commit is buffered. That must not be the commit which is
    /// being applied right now: the retry would fail as a duplicate, and the failure handling would
    /// then reload the conversation from under the operation still in progress. The replayed proposal
    /// must also be reported to the caller, since it has been stored.
    #[apply(all_cred_cipher)]
    async fn applying_buffered_commit_must_not_retry_itself(case: TestContext) {
        let [alice, bob, charlie] = case.sessions().await;
        let (conversation, missing_proposal) =
            alice_buffers_commit_missing_proposal(&case, [&alice, &bob, &charlie]).await;
        let conversation_id = conversation.id().clone();

        // Bob, at epoch 2, proposes something. Alice is still at epoch 1, so she buffers it.
        let proposal_guard = conversation.acting_as(&bob).await.invite_proposal(&charlie).await;
        let (proposal_guard, result) = proposal_guard.notify_member_fallible(&alice).await;
        assert!(matches!(
            result.unwrap_err(),
            Error::BufferedFutureMessage { message_epoch: 2 }
        ));
        let conversation = proposal_guard.finish();

        let decrypted = conversation
            .guard_of(&alice)
            .await
            .decrypt_message(&missing_proposal)
            .await
            .unwrap();
        let commit = decrypted
            .as_commit()
            .expect("the missing proposal must apply the buffered commit");
        assert!(
            matches!(
                commit.buffered_messages.as_deref(),
                Some([BufferedDecryptedMessage::Proposal(_)])
            ),
            "the replayed proposal must be reported as a proposal: {:?}",
            commit.buffered_messages
        );

        // A failed retry evicts the conversation from the cache, so this is how we observe that
        // the commit being applied was not retried.
        let still_cached = alice
            .session()
            .await
            .conversation_cache
            .lock()
            .await
            .remove(&conversation_id)
            .is_some();
        assert!(still_cached, "the commit being applied must not have been retried");
        assert_eq!(
            alice.transaction.count_entities().await.buffered_commits,
            0,
            "the buffered commit has applied, so it must no longer be buffered"
        );
    }

    /// A buffered commit which fails after merging must leave no trace, in memory or in the database.
    ///
    /// Merging writes the new epoch both to the in-memory group and to the database, and the steps after
    /// the merge can still fail. When that failure is swallowed so that the triggering proposal can
    /// succeed, both copies of the group have to be back at the old epoch; if only the database is
    /// rolled back, the in-memory group runs ahead of what is persisted. The proposal itself must
    /// still be stored and reported.
    ///
    /// We force the failure with an undecodable message in the pending-message buffer, which the
    /// buffered commit tries to replay only after it has merged.
    #[apply(all_cred_cipher)]
    async fn buffered_commit_failing_after_merge_must_roll_back_memory_and_database(case: TestContext) {
        let [alice, bob, charlie] = case.sessions().await;
        let (conversation, missing_proposal) =
            alice_buffers_commit_missing_proposal(&case, [&alice, &bob, &charlie]).await;
        let conversation_id = conversation.id().clone();

        // A protocol version and a public-message wire format, then a group id claiming five bytes
        // which aren't there: decoding the message fails after the wire format check.
        let undecodable = MlsPendingMessage {
            conversation_id: conversation_id.as_ref().into(),
            message: vec![0, 1, 0, 1, 5],
        };
        undecodable
            .save(alice.transaction.inner().unwrap().transaction())
            .unwrap();

        let mut alice_conversation = conversation.guard_of(&alice).await;
        let decrypted = alice_conversation.decrypt_message(&missing_proposal).await;
        assert!(
            matches!(decrypted, Ok(DecryptedMessage::Proposal(_))),
            "the commit failed, so the proposal's own result must be reported: {decrypted:?}"
        );
        assert_eq!(
            alice_conversation.epoch().await,
            1,
            "the in-memory group must have been rolled back to the epoch before the commit"
        );
        drop(alice_conversation);

        // Load the group afresh from the database.
        alice
            .session()
            .await
            .conversation_cache
            .lock()
            .await
            .remove(&conversation_id);
        let reloaded = alice.transaction.conversation(&conversation_id).await.unwrap();
        assert_eq!(
            reloaded.epoch().await,
            1,
            "the stored group must have been rolled back to the epoch before the commit"
        );
        assert_eq!(
            reloaded.group().await.pending_proposals().count(),
            1,
            "the proposal must still be stored"
        );
        drop(reloaded);

        assert_eq!(
            alice.transaction.count_entities().await.buffered_commits,
            0,
            "the failed commit must have been discarded"
        );
    }

    /// A buffered commit which can never apply must not poison every later proposal.
    ///
    /// Each incoming proposal retries the buffered commit, but the buffered commit is only cleared
    /// once it applies. If the group moves past the buffered commit's epoch by some other route
    /// before its missing proposal arrives, the retry can only ever fail. That failure must not
    /// replace the result of decrypting the proposal: the proposal is perfectly valid, and the
    /// stale commit is now useless and should be discarded. Otherwise every subsequent proposal
    /// fails with the same error for the lifetime of the conversation.
    #[apply(all_cred_cipher)]
    async fn stale_buffered_commit_must_not_fail_later_proposals(case: TestContext) {
        let [alice, bob, charlie] = case.sessions().await;
        let conversation = case.create_conversation([&alice, &bob, &charlie]).await;

        // Bob proposes removing Charlie at epoch 1, but nobody else is told about the proposal.
        let conversation = conversation
            .acting_as(&bob)
            .await
            .remove_proposal(&charlie)
            .await
            .finish();

        // Bob then commits it. The commit refers to the proposal by reference, so Alice, who never
        // received that proposal, cannot apply the commit, and buffers it to retry once she does.
        let commit_guard = conversation
            .acting_as(&bob)
            .await
            .commit_pending_proposals_unmerged()
            .await;
        let (commit_guard, result) = commit_guard.notify_member_fallible(&alice).await;
        assert!(matches!(result.unwrap_err(), Error::BufferedCommit));
        let conversation = commit_guard.finish();
        assert_eq!(
            alice.transaction.count_entities().await.buffered_commits,
            1,
            "the commit Alice could not apply must have been buffered"
        );

        // Before the proposal arrives, Alice updates her key material, and her commit wins:
        // everyone moves to epoch 2, and Bob's commit is discarded. Bob's buffered commit belongs
        // to epoch 1, so it can never apply now.
        let conversation = conversation
            .acting_as(&alice)
            .await
            .update()
            .await
            .notify_member(&bob)
            .await
            .notify_member(&charlie)
            .await
            .finish();

        // Two perfectly valid epoch 2 proposals arrive, from two different members.
        let proposal_guard = conversation.acting_as(&bob).await.remove_proposal(&charlie).await;
        let (proposal_guard, bob_proposal_result) = proposal_guard.notify_member_fallible(&alice).await;
        let conversation = proposal_guard.finish();

        let proposal_guard = conversation.acting_as(&charlie).await.remove_proposal(&bob).await;
        let (_proposal_guard, charlie_proposal_result) = proposal_guard.notify_member_fallible(&alice).await;

        assert!(
            bob_proposal_result.is_ok() && charlie_proposal_result.is_ok(),
            "valid proposals must decrypt regardless of the stale buffered commit\n\
                 bob's proposal: {bob_proposal_result:?}\n\
                 charlie's proposal: {charlie_proposal_result:?}"
        );
        assert_eq!(
            alice.transaction.count_entities().await.buffered_commits,
            0,
            "the stale buffered commit can never apply, so it must have been discarded"
        );
    }
}
