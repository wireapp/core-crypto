use core_crypto_keystore::{entities::PersistedMlsGroup, traits::EntityDeleteBorrowed};

use super::Result;
use crate::{KeystoreError, OpenMlsError, RecursiveError, mls::conversation::ConversationMut};

impl ConversationMut {
    /// Destroys a group locally
    ///
    /// # Errors
    /// KeyStore errors, such as IO
    pub async fn wipe(&mut self) -> Result<()> {
        // to the degree that it's easy, fallibly get things before doing any mutation
        let mut conversation_cache = self
            .tx_context
            .mls_groups()
            .await
            .map_err(RecursiveError::context("getting mls conversation cache"))?;

        self.mutate_group(async |transaction, group, _| {
            // collect all the relevant proposal refs without holding onto the group;
            // we'll need to mutate the group in shortly
            let proposals = group
                .pending_proposals()
                .map(|proposal| proposal.proposal_reference().to_owned())
                .collect::<Vec<_>>();
            for proposal in proposals {
                // Update proposals rekey the own leaf node. Hence the associated encryption keypair has to be cleared
                group
                    .remove_pending_proposal(transaction, &proposal)
                    .await
                    .map_err(OpenMlsError::wrap("removing pending proposal"))?;
            }

            Ok(())
        })
        .await?;

        let id = self.id();
        let context = self
            .tx_context
            .inner()
            .map_err(RecursiveError::context("getting inner context"))?;
        let tx = context.transaction();
        PersistedMlsGroup::delete_borrowed(tx, id.keystore()).map_err(KeystoreError::wrap("deleting mls group"))?;
        let _ = conversation_cache.remove(id);

        // Release the cache guard before clearing the buffers: that path reaches back into the
        // transaction context, and holding this guard across it would deadlock.
        drop(conversation_cache);

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::{mls::conversation::Error, test_utils::*};

    /// Wiping a conversation abandons the messages it had buffered.
    #[apply(all_cred_cipher)]
    async fn wipe_abandons_buffered_messages(case: TestContext) {
        Box::pin(async move {
            let [mut alice, bob] = case.sessions().await;
            let conversation = case.create_conversation([&alice, &bob]).await;

            // Bob advances the epoch without Alice hearing about it, then speaks in the new epoch.
            let conversation = conversation
                .acting_as(&bob)
                .await
                .update()
                .await
                .process_member_changes()
                .await
                .finish();
            let app_msg = conversation
                .guard_of(&bob)
                .await
                .encrypt_message(b"Hello Alice !")
                .await
                .unwrap();

            // Alice cannot decrypt a message from an epoch she has not reached yet, so she buffers it
            // until the commit which advances her own epoch arrives.
            let decrypt = conversation.guard_of(&alice).await.decrypt_message(app_msg).await;
            assert!(matches!(decrypt.unwrap_err(), Error::BufferedFutureMessage { .. }));
            assert_eq!(
                alice.transaction.count_entities().await.pending_messages,
                1,
                "the message Alice could not decrypt must have been buffered"
            );

            // That commit never arrives; Alice wipes the conversation instead.
            conversation.guard_of(&alice).await.wipe().await.unwrap();

            drop(conversation);
            alice.commit_transaction().await;

            let counts = alice.transaction.count_entities().await;
            assert_eq!(counts.group, 0, "the wipe must have removed the conversation");
            assert_eq!(
                counts.pending_messages, 0,
                "the buffered message belongs to a conversation which no longer exists, so wiping that \
                 conversation must have taken the message with it"
            );
        })
        .await
    }

    /// Wiping a conversation abandons the commit it had buffered.
    #[apply(all_cred_cipher)]
    async fn wipe_abandons_buffered_commits(case: TestContext) {
        Box::pin(async move {
            let [mut alice, bob, charlie] = case.sessions().await;
            let conversation = case.create_conversation([&alice, &bob, &charlie]).await;

            // Bob proposes removing Charlie, but nobody else is told about the proposal.
            let conversation = conversation
                .acting_as(&bob)
                .await
                .remove_proposal(&charlie)
                .await
                .finish();

            // Bob then commits it. The commit refers to the proposal by reference, so Alice — who never
            // received that proposal — cannot apply the commit, and buffers it to retry once she does.
            let commit_guard = conversation.acting_as(&bob).await.commit_pending_proposals().await;
            let (commit_guard, result) = commit_guard.notify_member_fallible(&alice).await;
            assert!(matches!(result.unwrap_err(), Error::BufferedCommit));
            let conversation = commit_guard.finish();

            assert_eq!(
                alice.transaction.count_entities().await.buffered_commits,
                1,
                "the commit Alice could not apply must have been buffered"
            );

            // The proposal never arrives; Alice wipes the conversation instead.
            conversation.guard_of(&alice).await.wipe().await.unwrap();

            drop(conversation);
            alice.commit_transaction().await;

            let counts = alice.transaction.count_entities().await;
            assert_eq!(counts.group, 0, "the wipe must have removed the conversation");
            assert_eq!(
                counts.buffered_commits, 0,
                "the buffered commit belongs to a conversation which no longer exists, so wiping that \
                 conversation must have taken the commit with it"
            );
        })
        .await
    }
}
