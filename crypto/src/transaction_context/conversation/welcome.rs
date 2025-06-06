//! This module contains transactional conversation operations that produce a [WelcomeBundle].

use std::borrow::BorrowMut as _;

use super::{Error, Result, TransactionContext};
use crate::{
    RecursiveError,
    mls::credential::crl::{extract_crl_uris_from_group, get_new_crl_distribution_points},
    prelude::{MlsConversation, MlsConversationConfiguration, MlsCustomConfiguration, WelcomeBundle},
};
use openmls::prelude::{MlsMessageIn, MlsMessageInBody};
use tls_codec::Deserialize as _;

impl TransactionContext {
    /// Create a conversation from a TLS serialized MLS Welcome message. The `MlsConversationConfiguration` used in this function will be the default implementation.
    ///
    /// # Arguments
    /// * `welcome` - a TLS serialized welcome message
    /// * `configuration` - configuration of the MLS conversation fetched from the Delivery Service
    ///
    /// # Return type
    /// This function will return the conversation/group id
    ///
    /// # Errors
    /// see [TransactionContext::process_welcome_message]
    #[cfg_attr(test, crate::dispotent)]
    pub async fn process_raw_welcome_message(
        &self,
        welcome: Vec<u8>,
        custom_cfg: MlsCustomConfiguration,
    ) -> Result<WelcomeBundle> {
        let mut cursor = std::io::Cursor::new(welcome);
        let welcome =
            MlsMessageIn::tls_deserialize(&mut cursor).map_err(Error::tls_deserialize("mls message in (welcome)"))?;
        self.process_welcome_message(welcome, custom_cfg).await
    }

    /// Create a conversation from a received MLS Welcome message
    ///
    /// # Arguments
    /// * `welcome` - a `Welcome` message received as a result of a commit adding new members to a group
    /// * `configuration` - configuration of the group/conversation
    ///
    /// # Return type
    /// This function will return the conversation/group id
    ///
    /// # Errors
    /// Errors can be originating from the KeyStore of from OpenMls:
    /// * if no [openmls::key_packages::KeyPackage] can be read from the KeyStore
    /// * if the message can't be decrypted
    #[cfg_attr(test, crate::dispotent)]
    pub async fn process_welcome_message(
        &self,
        welcome: MlsMessageIn,
        custom_cfg: MlsCustomConfiguration,
    ) -> Result<WelcomeBundle> {
        let MlsMessageInBody::Welcome(welcome) = welcome.extract() else {
            return Err(Error::CallerError(
                "the message provided to process_welcome_message was not a welcome message",
            ));
        };
        let cs = welcome.ciphersuite().into();
        let configuration = MlsConversationConfiguration {
            ciphersuite: cs,
            custom: custom_cfg,
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
        let conversation =
            MlsConversation::from_welcome_message(welcome, configuration, &mls_provider, mls_groups.borrow_mut())
                .await
                .map_err(RecursiveError::mls_conversation("creating conversation from welcome"))?;

        // We wait for the group to be created then we iterate through all members
        let crl_new_distribution_points = get_new_crl_distribution_points(
            &mls_provider,
            extract_crl_uris_from_group(&conversation.group)
                .map_err(RecursiveError::mls_credential("extracting crl uris from group"))?,
        )
        .await
        .map_err(RecursiveError::mls_credential("getting new crl distribution points"))?;

        let id = conversation.id.clone();
        mls_groups.insert(id.clone(), conversation);

        Ok(WelcomeBundle {
            id,
            crl_new_distribution_points,
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::test_utils::*;

    use super::*;

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

            // Ensure we're left with 1 less keypackage bundle in the store, because it was consumed with the OpenMLS Welcome message
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
            let commit = case.create_conversation([&alice]).await.invite([&bob]).await;
            let conversation = commit.conversation();
            let id = conversation.id().clone();
                // Meanwhile Bob creates a conversation with the exact same id as the one he's trying to join
                bob
                    .transaction
                    .new_conversation(&id, case.credential_type, case.cfg.clone())
                    .await
                    .unwrap();

                let welcome = conversation.transport().await.latest_welcome_message().await;
                let join_welcome = bob
                    .transaction
                    .process_welcome_message(welcome.into(), case.custom_cfg())
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
