use crate::{
    RecursiveError,
    mls::conversation::{Conversation as _, ConversationWithMls, conversation_guard::commit::TransportedCommitPolicy},
};

use super::{ConversationGuard, Result};

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
        let (_, mut commit) = self.add_members_inner(vec![key_package]).await?;

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
}
