//! This module contains transactional conversation operations that are related to processing welcome messages.

use const_format::formatcp;
use openmls::prelude::{MlsMessageIn, MlsMessageInBody};

use super::{Error, Result, TransactionContext};
use crate::{ConversationConfiguration, ConversationId, KeystoreError};

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

        // processing a welcome message deletes some data at the openmls level; we can't avoid it by simply
        // ordering things better. But what we can do is undelete it with a sql savepoint:
        // <https://sqlite.org/lang_savepoint.html>.
        //
        // we can use a const savepoint because we always either rollback or release the savepoint before exiting this
        // function (unless something goes wrong with accessing the database)
        const SAVEPOINT_NAME: &str = "process_welcome_message_savepoint";

        // we don't want to keep any of these guards around while openmls needs access to the db
        {
            let inner = self.inner().await?;
            let tx = inner.transaction();
            let conn = tx
                .conn()
                .map_err(KeystoreError::wrap("getting raw sql connection to create savepoint"))?;
            let mut stmt = conn
                .prepare_cached(formatcp!("SAVEPOINT {SAVEPOINT_NAME}"))
                .map_err(KeystoreError::wrap("creating savepoint creation stmt"))?;
            stmt.execute([]).map_err(KeystoreError::wrap("creating savepoint"))?;
        }

        let conversation_result = self
            .persist_conversation_from_welcome_message(welcome, configuration)
            .await;

        // now we pick up the guards again and either release or rollback our savepoint
        // a consequence of all this is that we can't avoid having keystore problems mask
        // a failed conversation persistence result.
        {
            let inner = self.inner().await?;
            let tx = inner.transaction();
            let conn = tx
                .conn()
                .map_err(KeystoreError::wrap("getting raw sql connection finalize savepoint"))?;

            if conversation_result.is_ok() {
                let mut stmt = conn
                    .prepare_cached(formatcp!("RELEASE SAVEPOINT {SAVEPOINT_NAME}"))
                    .map_err(KeystoreError::wrap("creating savepoint release stmt"))?;
                stmt.execute([]).map_err(KeystoreError::wrap("releasing savepoint"))?;
            } else {
                let mut stmt = conn
                    .prepare_cached(formatcp!("ROLLBACK TO SAVEPOINT {SAVEPOINT_NAME}"))
                    .map_err(KeystoreError::wrap("creating savepoint rollback stmt"))?;
                stmt.execute([])
                    .map_err(KeystoreError::wrap("rolling back savepoint"))?;
            }
        }

        let conversation = conversation_result?;
        let id = conversation.id().to_owned();

        Ok(id)
    }
}

#[cfg(test)]
mod tests {
    use crate::test_utils::*;

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
        use crate::LeafError;

        let [alice, mut bob] = case.sessions().await;
        Box::pin(async move {
            let credential_ref = &bob.initial_credential;
            let commit = case.create_conversation([&alice]).await.invite([&bob]).await;
            let conversation = commit.conversation();
            let id = conversation.id().clone();
                // Meanwhile Bob creates a conversation with the exact same id as the one he's trying to join
                bob
                    .transaction
                    .new_conversation(&id, credential_ref, case.cfg.clone())
                    .await
                    .unwrap();

                // Bob's key packages before processing the welcome
                let key_package_refs_before = bob.transaction.get_key_package_refs().await.unwrap();

                let welcome = conversation.transport().await.latest_welcome_message().await;

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
                assert!(innermost_source_matches!(join_welcome.unwrap_err(), LeafError::ConversationAlreadyExists(i) if i == &id));
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
        let credential_ref = &bob.initial_credential;
        let commit = case.create_conversation([&alice]).await.invite([&bob]).await;
        let conversation = commit.conversation();
        let id = conversation.id().clone();

        // Bob creates a conversation with the exact same id as the one he's trying to join, so
        // persisting the conversation from the welcome message is bound to fail
        bob.transaction
            .new_conversation(&id, credential_ref, case.cfg.clone())
            .await
            .unwrap();

        let welcome = conversation.transport().await.latest_welcome_message().await;

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

    /// Restoring the key material is only worth anything if it is complete: a key package whose
    /// private keys were not restored is unusable. So once the reason the welcome failed is gone,
    /// processing that same welcome message again has to succeed.
    #[apply(all_cred_cipher)]
    async fn restored_key_material_should_still_be_able_to_join_from_welcome(case: TestContext) {
        let [alice, bob] = case.sessions().await;
        let credential_ref = &bob.initial_credential;
        let commit = case.create_conversation([&alice]).await.invite([&bob]).await;
        let conversation = commit.conversation();
        let id = conversation.id().clone();

        // The conflicting conversation which makes the first attempt fail
        bob.transaction
            .new_conversation(&id, credential_ref, case.cfg.clone())
            .await
            .unwrap();

        let welcome = conversation.transport().await.latest_welcome_message().await;

        let join_welcome = bob.transaction.process_welcome_message(welcome.clone()).await;
        assert!(innermost_source_matches!(
            join_welcome.unwrap_err(),
            super::Error::ConversationAlreadyExists(i) if i == &id
        ));

        // Bob gets rid of the conversation which was in the way
        bob.transaction.conversation(&id).await.unwrap().wipe().await.unwrap();

        // The restored key material is complete, so the second attempt goes through
        let joined_id = bob.transaction.process_welcome_message(welcome).await.unwrap();
        assert_eq!(joined_id, id);

        // And the conversation Bob joined is the real thing: he can talk in it
        let message = bob
            .transaction
            .conversation(&id)
            .await
            .unwrap()
            .encrypt_message(b"hello")
            .await
            .unwrap();
        let decrypted = conversation
            .guard_of(&alice)
            .await
            .decrypt_message(&message)
            .await
            .unwrap();
        assert_eq!(decrypted.as_application_message().unwrap().plaintext, b"hello");
    }
}
