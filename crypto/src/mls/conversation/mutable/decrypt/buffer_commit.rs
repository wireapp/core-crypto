#[cfg(test)]
mod tests {
    use core_crypto_keystore::{
        entities::{InboxMessage, WaitingFor},
        traits::EntityDatabaseMutation as _,
    };
    use openmls::prelude::ContentType;

    use crate::{DecryptedMessage, test_utils::*};

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
        assert!(
            result.unwrap().is_empty(),
            "a deferred commit must not decrypt anything"
        );
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
            matches!(result.as_deref(), Ok([DecryptedMessage::Proposal(_)])),
            "the unrelated proposal must decrypt as a proposal, and nothing else: {result:?}"
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
            matches!(
                decrypted.as_slice(),
                [DecryptedMessage::Proposal(_), DecryptedMessage::Commit(_)]
            ),
            "the missing proposal must decrypt, then apply the buffered commit: {decrypted:?}"
        );
    }

    /// A buffered commit which applies must be removed from the buffer.
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
            matches!(
                decrypted.as_slice(),
                [DecryptedMessage::Proposal(_), DecryptedMessage::Commit(_)]
            ),
            "the missing proposal must decrypt, then apply the buffered commit: {decrypted:?}"
        );
        assert_eq!(
            alice.transaction.count_entities().await.buffered_commits,
            0,
            "the buffered commit has applied, so it must no longer be buffered"
        );
    }

    /// It's possible for one message to end up decrypting two proposals: a commit is pre-buffered
    /// waiting for the first proposal, and the second is a proposal in the new epoch.
    ///
    /// Decrypting the first proposal must successfully unbuffer not just the bound commit but the
    /// proposal which was waiting for the new epoch.
    #[apply(all_cred_cipher)]
    async fn applying_buffered_proposal_can_also_decrypt_another_buffered_proposal(case: TestContext) {
        let [alice, bob, charlie] = case.sessions().await;
        let (conversation, missing_proposal) =
            alice_buffers_commit_missing_proposal(&case, [&alice, &bob, &charlie]).await;

        // Bob, at epoch 2, proposes something. Alice is still at epoch 1, so she buffers it.
        let proposal_guard = conversation.acting_as(&bob).await.invite_proposal(&charlie).await;
        let (proposal_guard, result) = proposal_guard.notify_member_fallible(&alice).await;
        assert!(
            result.unwrap().is_empty(),
            "a proposal from a future epoch must be deferred"
        );
        let conversation = proposal_guard.finish();

        let decrypted = conversation
            .guard_of(&alice)
            .await
            .decrypt_message(&missing_proposal)
            .await
            .unwrap();
        assert!(
            matches!(
                decrypted.as_slice(),
                [
                    DecryptedMessage::Proposal(_),
                    DecryptedMessage::Commit(_),
                    DecryptedMessage::Proposal(_)
                ]
            ),
            "the missing proposal must apply the buffered commit, \
             and the replayed proposal must be reported as a proposal: {decrypted:?}"
        );
    }

    /// A message in the inbox which can't be decoded must not stop a buffered commit from applying.
    ///
    /// When a buffered commit applies, it replays whatever was waiting for its new epoch. A message
    /// there which can't even be parsed can never be replayed, so it is dropped, and the commit goes
    /// ahead. If it failed the commit instead, the epoch would be lost for the sake of a message
    /// which could never be read anyway.
    #[apply(all_cred_cipher)]
    async fn undecodable_inbox_message_must_not_block_buffered_commit(case: TestContext) {
        let [alice, bob, charlie] = case.sessions().await;
        let (conversation, missing_proposal) =
            alice_buffers_commit_missing_proposal(&case, [&alice, &bob, &charlie]).await;
        let conversation_id = conversation.id().clone();

        // A protocol version and a public-message wire format, then a group id claiming five bytes
        // which aren't there: decoding the message fails after the wire format check.
        // It waits for epoch 2, which Bob's buffered commit moves Alice into, so that the commit replays it.
        {
            let transaction = alice.transaction.inner().unwrap();
            let undecodable = InboxMessage {
                conversation_id: conversation_id.as_ref().into(),
                message: vec![0, 1, 0, 1, 5],
                content_type: ContentType::Application,
                waiting_for: WaitingFor::Epoch,
                epoch: 2,
                arrival_sequence: transaction.transaction().inbox_message_next_arrival_sequence(),
            };
            undecodable.save(transaction.transaction()).unwrap();
        }

        {
            let mut alice_conversation = conversation.guard_of(&alice).await;
            let decrypted = alice_conversation.decrypt_message(&missing_proposal).await;
            assert!(
                matches!(
                    decrypted.as_deref(),
                    Ok([DecryptedMessage::Proposal(_), DecryptedMessage::Commit(_)])
                ),
                "the proposal completes the buffered commit, which must apply, \
                 and the undecodable message must not be reported as replayed: {decrypted:?}"
            );
            assert_eq!(
                alice_conversation.epoch().await,
                2,
                "the in-memory group must have moved to the commit's epoch"
            );
        }

        // Load the group afresh from the database.
        alice
            .session()
            .await
            .conversation_cache
            .lock()
            .await
            .remove(&conversation_id);
        {
            let reloaded = alice.transaction.conversation(&conversation_id).await.unwrap();
            assert_eq!(
                reloaded.epoch().await,
                2,
                "the stored group must have moved to the commit's epoch"
            );
        }

        let counts = alice.transaction.count_entities().await;
        assert_eq!(
            counts.buffered_commits, 0,
            "the applied commit must have left the inbox"
        );
        assert_eq!(
            counts.pending_messages, 0,
            "the undecodable message must have been dropped from the inbox"
        );
    }

    /// A buffered commit must be discarded once the group moves past its epoch.
    ///
    /// A commit waiting for a missing proposal is only ever valid in the epoch it was created for.
    /// If the group bypasses the commit, the old commit must be discarded as stale.
    #[apply(all_cred_cipher)]
    async fn stale_buffered_commit_is_discarded_on_epoch_advance(case: TestContext) {
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
        assert!(
            result.unwrap().is_empty(),
            "a deferred commit must not decrypt anything"
        );
        let conversation = commit_guard.finish();
        assert_eq!(
            alice.transaction.count_entities().await.buffered_commits,
            1,
            "the commit Alice could not apply must have been buffered"
        );

        // Before the proposal arrives, Alice updates her key material, and her commit wins:
        // everyone moves to epoch 2, and Bob's commit is discarded. Bob's buffered commit belongs
        // to epoch 1, so it can never apply now.
        conversation
            .acting_as(&alice)
            .await
            .update()
            .await
            .notify_member(&bob)
            .await
            .notify_member(&charlie)
            .await
            .finish();

        assert_eq!(
            alice.transaction.count_entities().await.buffered_commits,
            0,
            "the stale buffered commit can never apply, so it must have been discarded"
        );
    }
}
