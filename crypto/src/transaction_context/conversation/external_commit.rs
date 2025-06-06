//! This module contains the implementation of [TransactionContext::join_by_external_commit].

use openmls::prelude::{MlsGroup, group_info::VerifiableGroupInfo};

use super::{Error, Result};
use crate::mls::conversation::pending_conversation::PendingConversation;
use crate::prelude::{MlsCommitBundle, WelcomeBundle};
use crate::{
    LeafError, MlsError, RecursiveError, mls,
    mls::credential::crl::{extract_crl_uris_from_group, get_new_crl_distribution_points},
    prelude::{
        ConversationId, MlsCiphersuite, MlsConversationConfiguration, MlsCredentialType, MlsCustomConfiguration,
        MlsGroupInfoBundle,
    },
    transaction_context::TransactionContext,
};

impl TransactionContext {
    /// Issues an external commit and stores the group in a temporary table. This method is
    /// intended for example when a new client wants to join the user's existing groups.
    /// On success this function will return the group id and a message to be fanned out to other
    /// clients.
    ///
    /// If the Delivery Service accepts the external commit, you have to ensure the commit is
    /// merged in order to get back a functional MLS group. If it rejects it, you can retry by
    /// calling [Self::join_by_external_commit] again.
    ///
    /// # Arguments
    /// * `group_info` - a GroupInfo wrapped in a MLS message. it can be obtained by deserializing a TLS serialized `GroupInfo` object
    /// * `custom_cfg` - configuration of the MLS conversation fetched from the Delivery Service
    /// * `credential_type` - kind of [openmls::prelude::Credential] to use for joining this group.
    ///   If [MlsCredentialType::Basic] is chosen and no Credential has been created yet for it,
    ///   a new one will be generated. When [MlsCredentialType::X509] is chosen, it fails when no
    ///   [openmls::prelude::Credential] has been created for the given Ciphersuite.
    ///
    /// # Returns [WelcomeBundle]
    ///
    /// # Errors
    /// Errors resulting from OpenMls, the KeyStore calls and serialization
    pub async fn join_by_external_commit(
        &self,
        group_info: VerifiableGroupInfo,
        custom_cfg: MlsCustomConfiguration,
        credential_type: MlsCredentialType,
    ) -> Result<WelcomeBundle> {
        let (commit_bundle, welcome_bundle, mut pending_conversation) = self
            .create_external_join_commit(group_info, custom_cfg, credential_type)
            .await?;

        let commit_result = pending_conversation.send_commit(commit_bundle).await;
        if let Err(err @ mls::conversation::Error::MessageRejected { .. }) = commit_result {
            pending_conversation
                .clear()
                .await
                .map_err(RecursiveError::mls_conversation("clearing external commit"))?;
            return Err(RecursiveError::mls_conversation("sending commit")(err).into());
        }
        commit_result.map_err(RecursiveError::mls_conversation("sending commit"))?;

        pending_conversation
            .merge()
            .await
            .map_err(RecursiveError::mls_conversation("merging from external commit"))?;

        Ok(welcome_bundle)
    }

    pub(crate) async fn create_external_join_commit(
        &self,
        group_info: VerifiableGroupInfo,
        custom_cfg: MlsCustomConfiguration,
        credential_type: MlsCredentialType,
    ) -> Result<(MlsCommitBundle, WelcomeBundle, PendingConversation)> {
        let client = &self.session().await?;

        let cs: MlsCiphersuite = group_info.ciphersuite().into();
        let mls_provider = self.mls_provider().await?;
        let cb = client
            .get_most_recent_or_create_credential_bundle(&mls_provider, cs.signature_algorithm(), credential_type)
            .await
            .map_err(RecursiveError::mls_client("getting or creating credential bundle"))?;

        let configuration = MlsConversationConfiguration {
            ciphersuite: cs,
            custom: custom_cfg.clone(),
            ..Default::default()
        };

        let (group, commit, group_info) = MlsGroup::join_by_external_commit(
            &mls_provider,
            &cb.signature_key,
            None,
            group_info,
            &configuration
                .as_openmls_default_configuration()
                .map_err(RecursiveError::mls_conversation(
                    "using configuration as openmls default configuration",
                ))?,
            &[],
            cb.to_mls_credential_with_key(),
        )
        .await
        .map_err(MlsError::wrap("joining mls group by external commit"))?;

        // We should always have ratchet tree extension turned on hence GroupInfo should always be present
        let group_info = group_info.ok_or(LeafError::MissingGroupInfo)?;
        let group_info = MlsGroupInfoBundle::try_new_full_plaintext(group_info).map_err(
            RecursiveError::mls_conversation("trying new full plaintext group info bundle"),
        )?;

        let crl_new_distribution_points = get_new_crl_distribution_points(
            &mls_provider,
            extract_crl_uris_from_group(&group)
                .map_err(RecursiveError::mls_credential("extracting crl uris from group"))?,
        )
        .await
        .map_err(RecursiveError::mls_credential("getting new crl distribution points"))?;

        let new_group_id = group.group_id().to_vec();

        let pending_conversation = PendingConversation::from_mls_group(group, custom_cfg, self.clone())
            .map_err(RecursiveError::mls_conversation("creating pending conversation"))?;
        pending_conversation
            .save()
            .await
            .map_err(RecursiveError::mls_conversation("saving pending conversation"))?;

        let commit_bundle = MlsCommitBundle {
            welcome: None,
            commit,
            group_info,
        };

        let welcome_bundle = WelcomeBundle {
            id: new_group_id,
            crl_new_distribution_points,
        };

        Ok((commit_bundle, welcome_bundle, pending_conversation))
    }

    pub(crate) async fn pending_conversation_exists(&self, id: &ConversationId) -> Result<bool> {
        match self.pending_conversation(id).await {
            Ok(_) => Ok(true),
            Err(Error::Leaf(LeafError::ConversationNotFound(_))) => Ok(false),
            Err(e) => Err(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use core_crypto_keystore::{CryptoKeystoreError, CryptoKeystoreMls, MissingKeyErrorKind};

    use super::Error;
    use crate::{LeafError, prelude::MlsConversationConfiguration, test_utils::*, transaction_context};

    #[apply(all_cred_cipher)]
    async fn join_by_external_commit_should_succeed(case: TestContext) {
        let [alice, bob] = case.sessions().await;
        Box::pin(async move {
            let conversation = case.create_conversation([&alice]).await;
            let id = conversation.id().clone();

            // Bob tries to join Alice's group
            let (external_commit, mut pending_conversation) = conversation.external_join_unmerged(&bob).await;

            // Alice acks the request and adds the new member
            assert_eq!(external_commit.conversation().member_count().await, 1);
            let (external_commit, result) = external_commit.notify_member_fallible(&alice).await;
            assert_eq!(external_commit.conversation().members_counted_by(&alice).await, 2);

            let decrypted = result.unwrap();
            // verify Bob's (sender) identity
            bob.verify_sender_identity(&case, &decrypted).await;

            // Let's say backend accepted our external commit.
            // So Bob can merge the commit and update the local state
            assert!(bob.transaction.conversation(&id).await.is_err());
            pending_conversation.merge().await.unwrap();
            let conversation = external_commit.notify_members().await;
            assert_eq!(conversation.member_count().await, 2);
            assert!(conversation.is_functional_and_contains([&alice, &bob]).await);

            // Pending group removed from keystore
            let error = bob
                .transaction
                .keystore()
                .await
                .unwrap()
                .mls_pending_groups_load(&id)
                .await;
            assert!(matches!(
                error.unwrap_err(),
                CryptoKeystoreError::MissingKeyInStore(MissingKeyErrorKind::MlsPendingGroup)
            ));

            // Ensure it's durable i.e. MLS group has been persisted
            bob.transaction
                .conversation(&id)
                .await
                .unwrap()
                .drop_and_restore()
                .await;
            assert!(conversation.is_functional_and_contains([&alice, &bob]).await);
        })
        .await
    }

    #[apply(all_cred_cipher)]
    async fn join_by_external_commit_should_be_retriable(case: TestContext) {
        let [alice, bob] = case.sessions().await;
        Box::pin(async move {
            let conversation = case.create_conversation([&alice]).await;

            // Bob tries to join Alice's group
            let (commit_guard, _pending_conversation) = conversation.external_join_unmerged(&bob).await;

            // BUT for some reason the Delivery Service will reject this external commit
            // e.g. another commit arrived meanwhile and the [GroupInfo] is no longer valid
            // But bob doesn't receive the rejection message, so the commit is still pending
            // as we didn't call .clear() on the pending conversation

            // Retrying
            let conversation = commit_guard.finish().external_join_notify(&bob).await;
            assert_eq!(conversation.member_count().await, 2);
            assert!(conversation.is_functional_and_contains([&alice, &bob]).await);
        })
        .await
    }

    #[apply(all_cred_cipher)]
    async fn should_fail_when_bad_epoch(case: TestContext) {
        use crate::mls;

        let [alice, bob] = case.sessions().await;
        Box::pin(async move {
            let conversation = case.create_conversation([&alice]).await;

            let commit_guard = conversation.external_join(&bob).await;
            let external_commit = commit_guard.message();

            // Alice creates a new commit before receiving the external join
            let conversation = commit_guard.finish().update_notify().await;

            // receiving the external join with outdated epoch should fail because of
            // the wrong epoch
            let result = conversation
                .guard()
                .await
                .decrypt_message(&external_commit.to_bytes().unwrap())
                .await;
            assert!(matches!(result.unwrap_err(), mls::conversation::Error::StaleCommit));
        })
        .await
    }

    #[apply(all_cred_cipher)]
    async fn existing_clients_can_join(case: TestContext) {
        let [alice, bob] = case.sessions().await;
        Box::pin(async move {
            let conversation = case.create_conversation([&alice, &bob]).await;
            // Alice can rejoin by external commit
            let conversation = conversation.external_join_notify(&alice).await;
            assert!(conversation.is_functional_and_contains([&alice, &bob]).await);
        })
        .await
    }

    #[apply(all_cred_cipher)]
    async fn should_fail_when_no_pending_external_commit(case: TestContext) {
        let [session] = case.sessions().await;
        let non_existent_id = conversation_id();
        // try to get a non-existent pending group
        let err = session
            .transaction
            .pending_conversation(&non_existent_id)
            .await
            .unwrap_err();

        assert!(matches!(
           err, Error::Leaf(LeafError::ConversationNotFound(id)) if non_existent_id == id
        ));
    }

    #[apply(all_cred_cipher)]
    async fn should_return_valid_group_info(case: TestContext) {
        let [alice, bob, charlie] = case.sessions().await;
        Box::pin(async move {
            let conversation = case.create_conversation([&alice]).await;

            // Bob tries to join Alice's group
            let conversation = conversation.external_join_notify(&bob).await;
            assert_eq!(conversation.member_count().await, 2);
            assert!(conversation.is_functional_and_contains([&alice, &bob]).await);

            // Now charlie wants to join with the [GroupInfo] from Bob's external commit
            let group_info = bob.mls_transport().await.latest_group_info().await;
            let bob_gi = group_info.get_group_info();
            let conversation = conversation.external_join_via_group_info_notify(&charlie, bob_gi).await;

            // Charlie is also in!
            assert_eq!(conversation.member_count().await, 3);
            assert!(conversation.is_functional_and_contains([&alice, &bob, &charlie]).await);
        })
        .await
    }

    #[apply(all_cred_cipher)]
    async fn clear_pending_group_should_succeed(case: TestContext) {
        let [alice, bob] = case.sessions().await;
        Box::pin(async move {
            let conversation = case.create_conversation([&alice]).await;

            let initial_count = alice.transaction.count_entities().await;

            // Bob tries to join Alice's group
            let (_, mut pending_conversation) = conversation.external_join_unmerged(&bob).await;

            // But for some reason, Bob wants to abort joining the group
            pending_conversation.clear().await.unwrap();

            let final_count = alice.transaction.count_entities().await;
            assert_eq!(initial_count, final_count);
        })
        .await
    }

    #[apply(all_cred_cipher)]
    async fn new_with_inflight_join_should_fail_when_already_exists(case: TestContext) {
        let [alice, bob] = case.sessions().await;
        Box::pin(async move {
            let conversation = case.create_conversation([&alice]).await;
            let id = conversation.id().clone();

            // Bob to join a conversation but while the server processes its request he
            // creates a conversation with the id of the conversation he's trying to join
            conversation.external_join(&bob).await;
            // erroneous call
            let conflict_join = bob
                .transaction
                .new_conversation(&id, case.credential_type, case.cfg.clone())
                .await;
            assert!(matches!(
                conflict_join.unwrap_err(),

                Error::Leaf(LeafError::ConversationAlreadyExists(i))
                if i == id
            ));
        })
        .await
    }

    #[apply(all_cred_cipher)]
    async fn new_with_inflight_welcome_should_fail_when_already_exists(case: TestContext) {
        use crate::mls;

        let [alice, bob] = case.sessions().await;
        Box::pin(async move {
            let conversation = case.create_conversation([&alice]).await;
            let id = conversation.id().clone();

                // While Bob tries to join a conversation via external commit he's also invited
                // to a conversation with the same id through a Welcome message
                let commit_guard = conversation.external_join(&bob).await;

                commit_guard.finish().invite([&bob]).await;

                let welcome = alice.mls_transport().await.latest_welcome_message().await;

                // erroneous call
                let conflict_welcome = bob
                    .transaction
                    .process_welcome_message(welcome.into(), case.custom_cfg())
                    .await;

                assert!(matches!(
                    conflict_welcome.unwrap_err(),
                    transaction_context::Error::Recursive(crate::RecursiveError::MlsConversation { source, .. })
                        if matches!(*source, mls::conversation::Error::Leaf(LeafError::ConversationAlreadyExists(ref i)) if i == &id
                        )
                ));
            })
        .await
    }

    #[apply(all_cred_cipher)]
    async fn should_fail_when_invalid_group_info(case: TestContext) {
        let [alice, bob, guest] = case.sessions().await;

        let conversation = case.create_conversation([&alice]).await.invite_notify([&bob]).await;

        // we need an invalid GroupInfo; let's manufacture one.
        let group_info = {
            let mut conversation = conversation.guard().await;
            let mut conversation = conversation.conversation_mut().await;
            let group = &mut conversation.group;
            let ct = group.credential().unwrap().credential_type();
            let cs = group.ciphersuite();
            let client = alice.session().await;
            let cb = client
                .find_most_recent_credential_bundle(cs.into(), ct.into())
                .await
                .unwrap();

            let gi = group
                .export_group_info(
                    &alice.transaction.mls_provider().await.unwrap(),
                    &cb.signature_key,
                    // joining by external commit assumes we include a ratchet tree, but this `false`
                    // says to leave it out
                    false,
                )
                .unwrap();
            gi.group_info().unwrap()
        };

        let join_ext_commit = guest
            .transaction
            .join_by_external_commit(group_info, case.custom_cfg(), case.credential_type)
            .await;

        assert!(innermost_source_matches!(
            join_ext_commit.unwrap_err(),
            crate::MlsErrorKind::MlsExternalCommitError(openmls::prelude::ExternalCommitError::MissingRatchetTree),
        ));
    }

    #[apply(all_cred_cipher)]
    async fn group_should_have_right_config(case: TestContext) {
        use crate::mls::conversation::ConversationWithMls as _;

        let [alice, bob] = case.sessions().await;
        Box::pin(async move {
            let conversation = case
                .create_conversation([&alice])
                .await
                .external_join_notify(&bob)
                .await
                .guard_of(&bob)
                .await;
            let conversation = conversation.conversation().await;
            let group = conversation.group();

            let capabilities = group.group_context_extensions().required_capabilities().unwrap();

            // see https://www.rfc-editor.org/rfc/rfc9420.html#section-11.1
            assert!(capabilities.extension_types().is_empty());
            assert!(capabilities.proposal_types().is_empty());
            assert_eq!(
                capabilities.credential_types(),
                MlsConversationConfiguration::DEFAULT_SUPPORTED_CREDENTIALS
            );
        })
        .await
    }
}
