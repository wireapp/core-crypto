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
    use crate::{mls::conversation::Error, test_utils::*};

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
        Box::pin(async move {
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
        })
        .await
    }
}
