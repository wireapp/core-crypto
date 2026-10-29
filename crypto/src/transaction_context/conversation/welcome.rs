//! This module contains transactional conversation operations that are related to processing welcome messages.

use openmls::prelude::{MlsMessageIn, MlsMessageInBody};

use super::{Error, Result, TransactionContext};
use crate::{ConversationConfiguration, ConversationId};

impl TransactionContext {
    /// Create a conversation from a received MLS Welcome message
    ///
    /// # Arguments
    /// * `welcome` - a `Welcome` message received as a result of a commit adding new members to a group
    ///
    /// # Return type
    /// This function will return the conversation/group id
    ///
    /// # Errors
    /// Errors can be originating from the KeyStore of from OpenMls:
    /// * if no [openmls::key_packages::KeyPackage] can be read from the KeyStore
    /// * if the message can't be decrypted
    #[cfg_attr(test, crate::dispotent)]
    pub async fn process_welcome_message(&self, welcome: impl Into<MlsMessageIn>) -> Result<ConversationId> {
        let MlsMessageInBody::Welcome(welcome) = welcome.into().extract() else {
            return Err(Error::CallerError(
                "the message provided to process_welcome_message was not a welcome message",
            ));
        };

        let configuration = ConversationConfiguration {
            cipher_suite: welcome.ciphersuite().into(),
            ..Default::default()
        };

        let inner = self.inner()?;
        let conversation = inner
            .transaction()
            .with_savepoint(
                "process_welcome_message_savepoint",
                async || {
                    self.persist_conversation_from_welcome_message(welcome, configuration)
                        .await
                },
                Error::savepoint,
            )
            .await?;

        let id = conversation.id().to_owned();

        Ok(id)
    }
}

#[cfg(test)]
mod tests {
    use crate::{ConversationId, test_utils::*};

    /// Create a conversation with `id` and commit to it once, so it's past epoch 0 and the welcome can't replace it.
    async fn create_conflicting_conversation(case: &TestContext, session: &SessionContext, id: &ConversationId) {
        session
            .transaction
            .new_conversation(id, &session.initial_credential, case.cfg.clone())
            .await
            .unwrap();
        session
            .transaction
            .conversation(id)
            .await
            .unwrap()
            .update_key_material()
            .await
            .unwrap();
    }

    #[apply(all_cred_cipher)]
    async fn joining_from_welcome_should_prune_local_key_material(case: TestContext) {
        let [alice, bob] = case.sessions().await;
        Box::pin(async move {
            // has to be before the original key_package count because it creates one
            // Create a conversation from alice, where she invites bob
            let commit_guard = case.create_conversation([&alice]).await.invite([&bob]).await;

            // Keep track of the whatever amount was initially generated
            let prev_count = bob.transaction.count_entities().await;
            // Bob accepts the welcome message, and as such, it should prune the used keypackage from the store
            commit_guard.notify_members().await;

            // Ensure we're left with 1 less keypackage bundle in the store, because it was consumed with the OpenMLS
            // Welcome message
            let next_count = bob.transaction.count_entities().await;
            assert_eq!(next_count.key_package, prev_count.key_package - 1);
            assert_eq!(next_count.hpke_private_key, prev_count.hpke_private_key - 1);
            assert_eq!(next_count.encryption_keypair, prev_count.encryption_keypair - 1);
        })
        .await;
    }

    #[apply(all_cred_cipher)]
    async fn process_welcome_should_fail_when_already_exists(case: TestContext) {
        let [alice, mut bob] = case.sessions().await;
        Box::pin(async move {
            let commit = case.create_conversation([&alice]).await.invite([&bob]).await;
            let conversation = commit.conversation();
            let id = conversation.id().clone();
                let welcome = conversation.transport().await.latest_welcome_message().await;

                // Meanwhile Bob creates a conversation with the exact same id as the one he's trying to join
                create_conflicting_conversation(&case, &bob, &id).await;

                // Bob's key packages before processing the welcome
                let key_package_refs_before = bob.transaction.get_key_package_refs().await.unwrap();

                // We need Bob's created key package to be persisted, so we can restore it on error.
                // Assuming that key package creation happens in its own transaction matches a sufficiently large
                // portion of real-world usage.
                bob.commit_transaction().await;

                let join_welcome = bob
                    .transaction
                    .process_welcome_message(welcome)
                    .await;

                // Bob's key packages after processing the welcome
                let key_package_refs_after = bob.transaction.get_key_package_refs().await.unwrap();

                assert!(!key_package_refs_before.is_empty());
                assert_eq!(key_package_refs_before, key_package_refs_after);
                assert!(innermost_source_matches!(join_welcome.unwrap_err(), super::Error::ConversationAlreadyExists(i) if i == &id));
            })
        .await;
    }

    /// Processing a welcome message makes openmls consume the key package it was addressed to; when
    /// persisting the conversation then fails, the savepoint in `process_welcome_message` must put
    /// that key material back.
    ///
    /// Unlike [`process_welcome_should_fail_when_already_exists`], this does not commit before
    /// processing the welcome: a savepoint rolls back within the transaction which created the key
    /// package, so restoration must work even then.
    #[apply(all_cred_cipher)]
    async fn failed_welcome_should_restore_key_material_in_same_transaction(case: TestContext) {
        let [alice, bob] = case.sessions().await;
        let commit = case.create_conversation([&alice]).await.invite([&bob]).await;
        let conversation = commit.conversation();
        let id = conversation.id().clone();

        let welcome = conversation.transport().await.latest_welcome_message().await;

        // Bob creates a conversation with the exact same id as the one he's trying to join, so
        // persisting the conversation from the welcome message is bound to fail
        create_conflicting_conversation(&case, &bob, &id).await;

        let count_before = bob.transaction.count_entities().await;
        let key_package_refs_before = bob.transaction.get_key_package_refs().await.unwrap();
        assert!(!key_package_refs_before.is_empty());

        let join_welcome = bob.transaction.process_welcome_message(welcome).await;
        assert!(innermost_source_matches!(
            join_welcome.unwrap_err(),
            super::Error::ConversationAlreadyExists(i) if i == &id
        ));

        // Every entity the welcome touched must be back where it was: the key package itself,
        // its hpke init private key, and its leaf node encryption keypair.
        let count_after = bob.transaction.count_entities().await;
        assert_eq!(count_before, count_after);
        let key_package_refs_after = bob.transaction.get_key_package_refs().await.unwrap();
        assert_eq!(key_package_refs_before, key_package_refs_after);
    }

    /// Losing a race to create a group leaves our own conversation at epoch 0, which the welcome replaces.
    #[apply(all_cred_cipher)]
    async fn process_welcome_should_replace_own_conversation_at_epoch_0(case: TestContext) {
        let [alice, bob] = case.sessions().await;
        let commit = case.create_conversation([&alice]).await.invite([&bob]).await;
        let id = commit.conversation().id().clone();

        bob.transaction
            .new_conversation(&id, &bob.initial_credential, case.cfg.clone())
            .await
            .unwrap();

        let conversation = commit.notify_members().await;
        assert!(conversation.is_functional_and_contains([&alice, &bob]).await);

        // Following Alice's next commit needs Bob's key material for the new group, so this shows the
        // wipe didn't delete it
        let conversation = conversation.advance_epoch().await;
        assert!(conversation.is_functional_and_contains([&alice, &bob]).await);
    }

    /// An external join we sent may already have been accepted, so replacing it with the welcome
    /// could add us twice.
    #[apply(all_cred_cipher)]
    async fn process_welcome_should_fail_when_pending_conversation_exists(case: TestContext) {
        let [alice, bob] = case.sessions().await;
        let conversation = case.create_conversation([&alice]).await;
        let id = conversation.id().clone();

        // Bob joins by external commit, but Alice doesn't see it and invites him instead
        let (external_join, _pending_conversation) = conversation.external_join_unmerged(&bob).await;
        let commit = external_join.finish().invite([&bob]).await;
        let welcome = commit.conversation().transport().await.latest_welcome_message().await;

        let join_welcome = bob.transaction.process_welcome_message(welcome).await;
        assert!(innermost_source_matches!(
            join_welcome.unwrap_err(),
            super::Error::ConversationAlreadyExists(i) if i == &id
        ));
        assert!(bob.transaction.pending_conversation_exists(&id).await.unwrap());
    }
}
