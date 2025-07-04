use std::collections::HashSet;

use itertools::{Either, Itertools as _};

use crate::{
    RecursiveError,
    mls::conversation::{Conversation as _, ConversationWithMls, conversation_guard::commit::TransportedCommitPolicy},
    prelude::{HistorySecret, MlsCommitBundle},
};

use super::{ConversationGuard, Error, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum HistoryClientUpdateOutcome {
    /// The conditions to update a history client have not been met
    NoUpdateNeeded,
    /// Updating the history client was successful.
    /// This process includes having sent the commit.
    CommitSentAndMerged,
}

impl ConversationGuard {
    /// Enable history sharing by generating a history client and adding it to the conversation.
    pub async fn enable_history_sharing(&mut self) -> Result<()> {
        if self.is_history_sharing_enabled().await {
            log::warn!("History sharing is already enabled.");
            return Ok(());
        }

        // Create a commit that adds a history client
        let history_secret = self.generate_history_secret().await?;
        let key_package = history_secret.key_package.clone().into();
        let (_, commit) = self.add_members_inner(vec![key_package]).await?;

        self.send_new_history_client_commit(commit, history_secret).await
    }

    /// Bundle the history secret with the commit and send it.
    async fn send_new_history_client_commit(
        &mut self,
        mut commit: MlsCommitBundle,
        history_secret: HistorySecret,
    ) -> Result<()> {
        // Merge the commit locally so that we can encrypt the history secret with the new state.
        self.merge_commit().await?;

        // Wrap and encrypt the history secret
        let transportable_history_secret = self
            .transport()
            .await?
            .prepare_for_transport(&history_secret)
            .await
            .map_err(RecursiveError::root("preparing for transport"))?;
        let encrypted_secret = self.encrypt_message(transportable_history_secret.as_slice()).await?;

        // Attach the encrypted history secret to the commit being sent
        commit.encrypted_message = Some(encrypted_secret);

        // In case sending succeeds but we fail to receive the response:
        // Before sending the commmit, announce the new history secret to the application.
        // If the DS rejects the commit we're creating below, we may have notified about a history
        // client that won't be used. This means another history client is going to be added for this history era.
        // The library consumer is expected to detect that this old history client is invalid and overwrite it with
        // the new one.
        self.session()
            .await?
            .notify_new_history_client(self.conversation().await.id().clone(), &history_secret)
            .await;

        let transported_commit_policy = self.send_commit(commit).await?;

        // We already merged the commit above, so being requested to merge the commit means we're in the correct state.
        assert_eq!(
            transported_commit_policy,
            TransportedCommitPolicy::Merge,
            "The transport was successful, so we should be requested to merge the commit"
        );

        Ok(())
    }

    /// Disable history sharing by removing history clients from the conversation.
    pub async fn disable_history_sharing(&mut self) -> Result<()> {
        let mut history_client_ids = self.get_client_ids().await;
        // We're facing a trade-off situation here: do we want to avoid unnecessary iteration and assume that there is always
        // at most one history client in a conversation?
        // Then we could use something like `into_iter().find_map()` to lazily evaluate client ids, but this way we're making sure to
        // remove any history client, and not just the first one we find.
        history_client_ids.retain(crate::ephemeral::is_history_client);

        if history_client_ids.is_empty() {
            log::warn!("History sharing is already disabled.");
            return Ok(());
        }

        self.remove_members(&history_client_ids).await
    }

    /// Updates the history client if
    /// - history sharing is enabled and
    /// - the currently pending commit contains a remove proposal for someone else than the history client.
    ///
    /// Updating the history client means adding a remove proposal for the existing, and an add proposal for
    /// a new history client.
    pub(super) async fn update_history_client(&mut self) -> Result<HistoryClientUpdateOutcome> {
        if !self.is_history_sharing_enabled().await {
            return Ok(HistoryClientUpdateOutcome::NoUpdateNeeded);
        }

        let conversation = self.conversation().await;
        let Some(pending_commit) = conversation.group().pending_commit() else {
            return Err(Error::PendingCommitNotFound);
        };

        let removed_indices = pending_commit
            .remove_proposals()
            .map(|p| p.remove_proposal().removed())
            .collect::<HashSet<_>>();
        // If no one was removed, we can keep the existing history client.
        if removed_indices.is_empty() {
            return Ok(HistoryClientUpdateOutcome::NoUpdateNeeded);
        }

        // Distinguish between history clients and other clients for the following operations
        let (existing_history_clients, other_clients): (HashSet<_>, HashSet<_>) =
            conversation.group().members().partition_map(|member| {
                let is_history_client = crate::ephemeral::is_history_client(&member.credential.identity().into());
                let member_index = member.index;
                if is_history_client {
                    Either::Left(member_index)
                } else {
                    Either::Right(member_index)
                }
            });

        // If all history clients are being removed (e.g., when disabling history sharing), there's nothing to do.
        if existing_history_clients
            .iter()
            .all(|index| removed_indices.contains(index))
        {
            return Ok(HistoryClientUpdateOutcome::NoUpdateNeeded);
        }

        // If no other clients are being removed, there is also nothig to do
        if !other_clients.iter().any(|index| removed_indices.contains(index)) {
            return Ok(HistoryClientUpdateOutcome::NoUpdateNeeded);
        }

        // If we're still here, all conditions are met to update the history client.

        // First, restore the proposals from the pending commit before clearing it.
        let pending_proposals = pending_commit
            .queued_proposals()
            .map(|proposal| proposal.proposal())
            .cloned()
            .collect::<Vec<_>>();
        drop(conversation);

        self.clear_pending_commit().await?;

        let session = &self.session().await?;
        let provider = &self.crypto_provider().await?;
        let history_secret = self.generate_history_secret().await?;
        let key_package = history_secret.key_package.clone().into();

        let mut conversation = self.conversation_mut().await;

        // Propose to remove the old history client
        for history_client in existing_history_clients {
            conversation
                .propose_remove_member(session, provider, history_client)
                .await?;
        }

        // Propose to add a new history client
        conversation.propose_add_member(session, provider, key_package).await?;

        // We're getting the proposals we just created from the pending proposals queue, as the previously
        // called `propose_remove()` and `propose_add()` pushed them to that queue as a side effect.
        let remove_and_add = conversation
            .self_pending_proposals()
            .map(|proposal| proposal.proposal())
            .cloned()
            .collect();

        drop(conversation);

        let inline_proposals = [pending_proposals, remove_and_add].concat();

        let commit = self
            .commit_inline_proposals(inline_proposals)
            .await?
            .expect("we just added a proposal, so this will create a commit");

        self.send_new_history_client_commit(commit, history_secret).await?;

        Ok(HistoryClientUpdateOutcome::CommitSentAndMerged)
    }
}

#[cfg(test)]
mod tests {
    use rstest::rstest;
    use rstest_reuse::apply;

    use crate::ephemeral::HISTORY_CLIENT_ID_PREFIX;
    use crate::mls::conversation::Conversation;
    use crate::test_utils::{TestContext, all_cred_cipher};

    #[apply(all_cred_cipher)]
    /// Together with the tests in [crate::ephemeral] this proves that we can create ephemeral clients from the
    /// events emitted by enabling history sharing.
    async fn enable_disable_history_sharing(case: TestContext) {
        let [alice, bob] = case.sessions().await;
        Box::pin(async move {
            let test_conv = case.create_conversation([&alice, &bob]).await;
            let guard = test_conv.guard().await;

            assert!(!guard.is_history_sharing_enabled().await);

            let test_conv = test_conv.enable_history_sharing_notify().await;
            assert_eq!(test_conv.member_count().await, 3);
            let add_history_client_commit = alice.mls_transport().await.latest_commit_bundle().await;
            let encrypyed_history_secret = add_history_client_commit
                .encrypted_message
                .expect("history secret should be bundled with the commmit");
            test_conv
                .guard_of(&bob)
                .await
                .decrypt_message(&encrypyed_history_secret)
                .await
                .expect("bob should be able to decrypt the history secret");

            let test_conv = test_conv.disable_history_sharing_notify().await;
            assert!(!guard.is_history_sharing_enabled().await);
            assert_eq!(test_conv.member_count().await, 2);

            let observed_history_clients = alice.history_observer().await.observed_history_clients().await;
            assert_eq!(
                observed_history_clients.len(),
                1,
                "we triggered exactly one history client change and so should observe that"
            );
            assert_eq!(
                observed_history_clients[0].0,
                test_conv.id().clone(),
                "conversation id of observed history client change must match"
            );
            assert!(
                observed_history_clients[0]
                    .1
                    .client_id
                    .starts_with(HISTORY_CLIENT_ID_PREFIX.as_bytes()),
                "client id of observed history client change must be a history client id"
            );
        })
        .await
    }

    #[apply(all_cred_cipher)]
    async fn should_update_history_client_on_member_remove(case: TestContext) {
        let [alice, bob, carol] = case.sessions().await;
        Box::pin(async move {
            let test_conv = case.create_conversation([&alice, &bob, &carol]).await;
            let guard = test_conv.guard().await;

            assert!(!guard.is_history_sharing_enabled().await);
            assert_eq!(test_conv.member_count().await, 3, "we have 3 members in the beginning");

            let test_conv = test_conv.enable_history_sharing_notify().await;
            assert_eq!(
                test_conv.member_count().await,
                4,
                "after history sharing was enabled, we have one more member"
            );

            let test_conv = test_conv.remove_notify(&carol).await;

            let observed_history_clients = alice.history_observer().await.observed_history_clients().await;
            assert_eq!(
                observed_history_clients.len(),
                2,
                "we triggered exactly two history client changes and so should observe that"
            );
            assert!(
                observed_history_clients
                    .iter()
                    .all(|observation| observation.1.client_id.starts_with(HISTORY_CLIENT_ID_PREFIX.as_bytes())),
                "client ids of observed history client changes must be a history client id"
            );
            assert_eq!(
                test_conv.member_count().await,
                3,
                "after removing one member, we have 3 members, including the new history client"
            );

            let remove_carol_commit = alice.mls_transport().await.latest_commit_bundle().await;
            let encrypyed_history_secret = remove_carol_commit
                .encrypted_message
                .expect("history secret should be bundled with the commmit");
            test_conv
                .guard_of(&bob)
                .await
                .decrypt_message(&encrypyed_history_secret)
                .await
                .expect("bob should be able to decrypt the history secret");
        })
        .await
    }

    #[apply(all_cred_cipher)]
    /// In this test, we're testing our mls library. However, our current mls fork doesn't have this test, and we require this behavior
    /// for history sharing, that's why this test lives here, for now.
    async fn can_remove_two_and_add_one_member_in_commit(case: TestContext) {
        // This many members are initially in the conversation.
        const INITIAL_MEMBERS_COUNT: usize = 6;
        // This many members are removed from the conversation.
        const REMOVED_MEMBERS_COUNT: usize = 2;
        // This many members are invited to the conversation.
        const INVITED_MEMBERS_COUNT: usize = 1;

        const ALL_MEMBERS_COUNT: usize = REMAINING_MEMBERS_COUNT + REMOVED_MEMBERS_COUNT + INVITED_MEMBERS_COUNT;
        const REMAINING_MEMBERS_COUNT: usize = INITIAL_MEMBERS_COUNT - REMOVED_MEMBERS_COUNT;

        Box::pin(async move {
            let all_members = case.sessions::<ALL_MEMBERS_COUNT>().await;
            let initial_members = &all_members[..INITIAL_MEMBERS_COUNT];
            let removed_members = &all_members[REMAINING_MEMBERS_COUNT..INITIAL_MEMBERS_COUNT];
            let invited_members = &all_members[INITIAL_MEMBERS_COUNT..];
            let mut conv = case.create_conversation(initial_members).await;
            assert_eq!(conv.member_count().await, INITIAL_MEMBERS_COUNT);

            for member in removed_members {
                conv = conv
                    .acting_as(&all_members[1])
                    .await
                    .remove_proposal_notify(member)
                    .await;
            }

            for member in invited_members {
                conv = conv.invite_proposal_notify(member).await;
            }

            let conv = conv.commit_pending_proposals_notify().await;

            assert_eq!(
                conv.member_count().await,
                REMAINING_MEMBERS_COUNT + INVITED_MEMBERS_COUNT
            );
        })
        .await
    }
}
