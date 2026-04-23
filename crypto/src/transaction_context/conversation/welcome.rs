//! This module contains transactional conversation operations that are related to processing welcome messages.

use std::borrow::BorrowMut as _;

use openmls::prelude::{MlsMessageIn, MlsMessageInBody};

use super::{Error, Result, TransactionContext};
use crate::{ConversationId, MlsConversation, MlsConversationConfiguration, RecursiveError};

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
        let database = &self.database().await?;
        let MlsMessageInBody::Welcome(welcome) = welcome.into().extract() else {
            return Err(Error::CallerError(
                "the message provided to process_welcome_message was not a welcome message",
            ));
        };
        let cs = welcome.ciphersuite().into();
        let configuration = MlsConversationConfiguration {
            ciphersuite: cs,
            ..Default::default()
        };
        let mls_provider = self
            .mls_provider()
            .await
            .map_err(RecursiveError::transaction("getting mls provider"))?;
        let mut mls_groups = self
            .mls_groups()
            .await
            .map_err(RecursiveError::transaction("getting mls groups"))?;
        let conversation = MlsConversation::from_welcome_message(
            welcome,
            configuration,
            &mls_provider,
            database,
            mls_groups.borrow_mut(),
        )
        .await
        .map_err(RecursiveError::mls_conversation("creating conversation from welcome"))?;

        let id = conversation.id.clone();
        mls_groups.insert(&id, conversation);

        Ok(id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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

        let [alice, bob] = case.sessions().await;
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

                let welcome = conversation.transport().await.latest_welcome_message().await;
                let join_welcome = bob
                    .transaction
                    .process_welcome_message(welcome)
                    .await;
                assert!(
                    matches!(join_welcome.unwrap_err(),
                    Error::Recursive(crate::RecursiveError::MlsConversation { source, .. })
                        if matches!(*source, crate::mls::conversation::Error::Leaf(LeafError::ConversationAlreadyExists(ref i)) if i == &id
                        )
                    )
                );
            })
        .await;
    }
}
