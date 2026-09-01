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
}
