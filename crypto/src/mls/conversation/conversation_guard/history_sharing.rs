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

        let transported_commit_policy = self.send_commit(commit).await?;

        // We already merged the commit above, so being requested to merge the commit means we're in the correct state.
        assert_eq!(
            transported_commit_policy,
            TransportedCommitPolicy::Merge,
            "The transport was successful, so we should be requested to merge the commit"
        );

        // Now we can announce that a new history client has successfully been added for this conversation.
        self.session()
            .await?
            .notify_new_history_client(self.conversation().await.id().clone(), &history_secret)
            .await;

        Ok(())
    }
}
