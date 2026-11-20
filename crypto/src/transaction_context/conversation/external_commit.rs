//! This module contains the implementation of [TransactionContext::join_by_external_commit].

use core_crypto_keystore::{entities::InboxMessage, traits::DeletableBySearchKey as _};
use openmls::prelude::{LeafNodeParameters, MlsGroup, group_info::VerifiableGroupInfo};
use openmls_traits::OpenMlsProvider as _;

use crate::{
    CommitBundle, ConversationConfiguration, ConversationId, CredentialRef, KeystoreError, OpenMlsError,
    RecursiveError,
    mls::{
        self,
        conversation::{ConversationIdRef, ConversationMut, PendingConversation},
        credential::validation::validate_credentials,
    },
    transaction_context::{Error, Result, TransactionContext},
};

impl TransactionContext {
    /// Issues an external commit and stores the group as a pending row. This method is intended
    /// for example when a new client wants to join the user's existing groups, or as a recovery
    /// mechanism to rejoin a conversation whose local state has desynchronized beyond repair.
    /// On success this function will return the group id and a message to be fanned out to other
    /// clients.
    ///
    /// If the Delivery Service accepts the external commit, you have to ensure the commit is
    /// merged in order to get back a functional MLS group. If it rejects it, you can retry by
    /// calling [Self::join_by_external_commit] again.
    ///
    /// If the Delivery Service rejects the commit, everything this did is undone: in particular, a conversation
    /// being rejoined is left as it was. If sending fails for any other reason, or merging fails, the pending
    /// conversation is kept in the transaction so the join can be recovered. **That replaces any conversation
    /// being rejoined,** and the previous state can't be recovered, even if the join never succeeds. Whether the
    /// kept state survives is up to the caller: by default an error crossing the FFI aborts the transaction and
    /// rolls it back. This is fine because the only reason to call this on a conversation you already have is that
    /// its local state is already considered unusable — that is what "rejoin" means here — so there is nothing worth
    /// preserving in the state it replaces.
    ///
    /// If this join is a rejoin of an existing group, any messages currently buffered for that group are discarded.
    ///
    /// # Arguments
    /// * `group_info` - a GroupInfo wrapped in an MLS message. it can be obtained by deserializing a TLS serialized
    ///   `GroupInfo` object
    /// * `credential_ref` - reference to the [crate::Credential] to use for joining this group.
    ///
    /// # Returns [ConversationId]
    ///
    /// # Errors
    /// Errors resulting from OpenMls, the KeyStore calls and serialization
    pub async fn join_by_external_commit(
        &self,
        group_info: VerifiableGroupInfo,
        credential_ref: &CredentialRef,
    ) -> Result<ConversationId> {
        let inner = self.inner()?;
        // The outer result decides what happens to the savepoint. An error rolls back everything the join wrote.
        // `Ok(Err(_))` keeps the pending conversation, for a join that failed in a way it can recover from.
        inner
            .with_savepoint(
                "join_by_external_commit",
                async || {
                    let (commit_bundle, id, mut pending_conversation) =
                        self.create_external_join_commit(group_info, credential_ref).await?;

                    if let Err(err) = pending_conversation.send_commit(commit_bundle).await {
                        let is_message_rejected = matches!(err, mls::conversation::Error::MessageRejected { .. });
                        let err = RecursiveError::context("sending commit")(err).into();
                        return if is_message_rejected { Err(err) } else { Ok(Err(err)) };
                    }

                    Ok(pending_conversation
                        .merge()
                        .await
                        .map(|()| id)
                        .map_err(|err| RecursiveError::context("merging from external commit")(err).into()))
                },
                Error::savepoint,
            )
            .await?
    }

    /// Build an external commit to join a group, and store the group as pending.
    ///
    /// openmls merges an external commit as soon as it has built it, so the stored group is already in the epoch
    /// the commit starts. It stays marked pending until the Delivery Service has accepted the commit.
    pub(crate) async fn create_external_join_commit(
        &self,
        group_info: VerifiableGroupInfo,
        credential_ref: &CredentialRef,
    ) -> Result<(CommitBundle, ConversationId, PendingConversation)> {
        let inner = self.inner()?;
        let crypto_provider = self.crypto_provider().await?;
        let provider = crypto_provider.with_transaction(inner.transaction());
        let credential = credential_ref
            .load(&inner.transaction)
            .await
            .map_err(RecursiveError::context("loading credential"))?;

        let ciphersuite = group_info.ciphersuite();
        let group_id = group_info.group_id().clone();
        let id = ConversationIdRef::new(group_id.as_slice()).to_owned();

        let configuration = ConversationConfiguration {
            cipher_suite: ciphersuite.into(),
            ..Default::default()
        };
        let verified_group = MlsGroup::external_commit_builder()
            .with_config(configuration.as_openmls_join_config())
            .verify_group(&provider, group_info)
            .map_err(OpenMlsError::wrap("verifying the group to join by external commit"))?;
        // Check the members before anything is written.
        validate_credentials(
            crypto_provider.authentication_service(),
            &verified_group
                .members()
                .map(|member| member.credential)
                .collect::<Vec<_>>(),
        )
        .await
        .map_err(RecursiveError::mls_credential(
            "checking the credentials of the group we're joining",
        ))?;

        // A rejoin, or a retry of a pending join.
        if self.conversation_exists(&id, None).await? {
            if self.conversation_exists(&id, Some(false)).await? {
                // rejoining replaces the group without going through `mutate_group`, so we have to
                // capture epoch data from an existing group here
                let conversation = self.conversation(&id).await?;
                conversation
                    .record_epoch_data(conversation.group().await.mls_group())
                    .await
                    .map_err(RecursiveError::context("recording epoch data before rejoin"))?;
            }

            // The group we build replaces this one. Drop openmls's state of the old group, so none of it outlives
            // it. The row, which other tables refer to, stays.
            if let Some(mut group) = MlsGroup::load(provider.storage(), &group_id)
                .map_err(KeystoreError::wrap("loading the group we're replacing"))?
            {
                group
                    .delete(provider.storage())
                    .map_err(KeystoreError::wrap("deleting the state of the group we're replacing"))?;
            }
            self.mls_groups().await?.remove(&id);
        }

        // openmls writes the group into its row, so the row has to exist first.
        self.insert_group_row(&id, &credential_ref.keystore_pk(), true)?;

        let (_, bundle) = verified_group
            .build_group(&provider, credential.to_mls_credential_with_key())
            .map_err(OpenMlsError::wrap("building the group to join by external commit"))?
            // Our new leaf has to support what the group requires, X509 credentials among them.
            .leaf_node_parameters(
                LeafNodeParameters::builder()
                    .with_capabilities(ConversationConfiguration::default_leaf_capabilities())
                    .build(),
            )
            .load_psks(provider.storage())
            .map_err(OpenMlsError::wrap("loading psks for the external commit"))?
            .build(
                provider.rand(),
                provider.crypto(),
                &credential.signature_key_pair,
                |_| true,
            )
            .map_err(OpenMlsError::wrap("building the external commit"))?
            .finalize(&provider)
            .map_err(OpenMlsError::wrap("finalizing the external commit"))?;

        let commit_bundle =
            ConversationMut::commit_bundle(bundle).map_err(RecursiveError::context("bundling the external commit"))?;

        // Having just built a join commit, we clear any inbox messages which may be stored.
        //
        // Three cases:
        //
        // 1. Fresh join: nothing can be in the inbox, no effect, harmless.
        // 2. Rejoin: gets rid of the old group's leftovers, which wouldn't decrypt with the new group anyway.
        // 3. Retrying a pending join: also clears messages buffered against the pending group; as we're currently
        //    replacing that, we couldn't have decrypted them anyway.
        InboxMessage::delete_all_matching(inner.transaction(), id.keystore()).map_err(KeystoreError::wrap(
            "deleting all inbox messages for conversation when creating external join commit",
        ))?;

        let pending_conversation = PendingConversation::new(id.clone(), self.clone());
        Ok((commit_bundle, id, pending_conversation))
    }
}

#[cfg(test)]
mod tests {

    use core_crypto_keystore::{entities::PersistedMlsGroup, traits::FetchFromDatabase as _};

    use crate::{ConversationConfiguration, test_utils::*, transaction_context::Error};

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

            let decrypted = result.unwrap().into_single();
            // verify Bob's (sender) identity
            bob.verify_sender_identity(&case, &bob.initial_credential, &decrypted)
                .await;

            // Let's say backend accepted our external commit.
            // So Bob can merge the commit and update the local state
            assert!(bob.transaction.conversation(&id).await.is_err());
            pending_conversation.merge().await.unwrap();
            let conversation = external_commit.notify_members().await;
            assert_eq!(conversation.member_count().await, 2);
            assert!(conversation.is_functional_and_contains([&alice, &bob]).await);

            // The group's row is no longer marked pending: it's the same row, now established.
            let keystore_id = id.as_ref().keystore();
            let group = bob
                .transaction
                .database()
                .unwrap()
                .get_borrowed::<PersistedMlsGroup>(keystore_id)
                .await
                .unwrap()
                .unwrap();
            assert!(!group.is_pending);

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
            let credential_ref = &bob.initial_credential;
            // erroneous call
            let conflict_join = bob
                .transaction
                .new_conversation(&id, credential_ref, case.cfg.clone())
                .await;
            assert!(matches!(
                conflict_join.unwrap_err(),

                Error::ConversationAlreadyExists(i)
                if i == id
            ));
        })
        .await
    }

    #[apply(all_cred_cipher)]
    async fn new_with_inflight_welcome_should_fail_when_already_exists(case: TestContext) {
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
                    .process_welcome_message(welcome)
                    .await;

                assert!(innermost_source_matches!(conflict_welcome.unwrap_err(), Error::ConversationAlreadyExists(i) if i == &id));
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
            let (cipher_suite, credential_type) = {
                let credential_type = conversation
                    .group()
                    .await
                    .credential()
                    .unwrap()
                    .credential_type()
                    .try_into()
                    .expect("case conversation has a known credential type");
                let cipher_suite = conversation.group().await.ciphersuite();
                (cipher_suite, credential_type)
            };
            let credential = alice.find_any_credential(cipher_suite.into(), credential_type).await;
            let mls_provider = alice.transaction.crypto_provider().await.unwrap();
            conversation
                .mutate_group_test(async move |_, group, _| {
                    let gi = group
                        .export_group_info(
                            mls_provider.crypto(),
                            &credential.signature_key_pair,
                            // joining by external commit assumes we include a ratchet tree, but this `false`
                            // says to leave it out
                            false,
                        )
                        .unwrap();
                    Ok(gi.group_info().unwrap())
                })
                .await
                .unwrap()
        };

        let join_ext_commit = guest
            .transaction
            .join_by_external_commit(group_info, &guest.initial_credential)
            .await;

        assert!(innermost_source_matches!(
            join_ext_commit.unwrap_err(),
            crate::OpenMlsErrorKind::MlsExternalCommitBuilderError(
                openmls::prelude::ExternalCommitBuilderError::MissingRatchetTree
            ),
        ));
    }

    #[apply(all_cred_cipher)]
    async fn group_should_have_right_config(case: TestContext) {
        let [alice, bob] = case.sessions().await;
        Box::pin(async move {
            let conversation = case
                .create_conversation([&alice])
                .await
                .external_join_notify(&bob)
                .await
                .guard_of(&bob)
                .await;
            let group = &conversation.group().await;

            let capabilities = group.extensions().required_capabilities().unwrap();

            // see https://www.rfc-editor.org/rfc/rfc9420.html#section-11.1
            assert!(capabilities.extension_types().is_empty());
            assert!(capabilities.proposal_types().is_empty());
            assert_eq!(
                capabilities.credential_types(),
                ConversationConfiguration::DEFAULT_SUPPORTED_CREDENTIALS
            );
        })
        .await
    }

    /// Starting a rejoin discards the messages the old group had buffered, but messages which arrive while the
    /// rejoin is pending belong to the new group, so they are replayed once the join commit is merged.
    #[apply(all_cred_cipher)]
    async fn rejoin_discards_old_buffered_messages_but_replays_those_received_while_pending(case: TestContext) {
        let [alice, bob] = case.sessions().await;
        let conversation = case.create_conversation([&alice, &bob]).await;

        // Alice misses Bob's commit, so she has to buffer the message he sends after it.
        let commit_guard = conversation.acting_as(&bob).await.update().await;
        let stale_message = commit_guard
            .conversation()
            .guard()
            .await
            .encrypt_message("stale")
            .await
            .unwrap();
        let conversation = commit_guard.finish();
        let decrypted = alice
            .transaction
            .decrypt_message(conversation.id(), stale_message)
            .await
            .unwrap();
        assert!(
            decrypted.is_empty(),
            "Alice can't decrypt Bob's message without his commit"
        );
        assert_eq!(alice.transaction.count_entities().await.pending_messages, 1);

        // Alice gives up on her desynchronized state and rejoins. The DS hasn't confirmed her join yet.
        let (commit_guard, _pending_conversation) =
            conversation.acting_as(&bob).await.external_join_unmerged(&alice).await;
        assert_eq!(
            alice.transaction.count_entities().await.pending_messages,
            0,
            "starting the rejoin must discard the messages buffered for the old group"
        );
        let join_commit = commit_guard.message().to_bytes().unwrap();

        // Bob accepts Alice's join, then speaks in the new epoch before Alice has seen her own join commit.
        let conversation = commit_guard.notify_members().await;
        let fresh_message = conversation
            .guard_of(&bob)
            .await
            .encrypt_message("fresh")
            .await
            .unwrap();
        let decrypted = alice
            .transaction
            .decrypt_message(conversation.id(), fresh_message)
            .await
            .unwrap();
        assert!(
            decrypted.is_empty(),
            "Alice's rejoin is still pending, so she must defer Bob's message"
        );
        assert_eq!(alice.transaction.count_entities().await.pending_messages, 1);

        // Alice's join commit arrives: she merges it, then replays the message Bob sent in the meantime.
        let mut decrypted = alice
            .transaction
            .decrypt_message(conversation.id(), join_commit)
            .await
            .unwrap()
            .into_iter();
        assert!(
            decrypted.next().unwrap().is_commit(),
            "the first message must be Alice's own join commit"
        );
        let replayed = decrypted
            .map(|message| message.into_application_message().unwrap().plaintext)
            .collect::<Vec<_>>();
        assert_eq!(replayed, [b"fresh".to_vec()]);
        assert_eq!(alice.transaction.count_entities().await.pending_messages, 0);
        assert!(conversation.is_functional_and_contains([&alice, &bob]).await);
    }

    /// A new attempt to join replaces the previous one, so messages buffered for the previous attempt are discarded.
    #[apply(all_cred_cipher)]
    async fn retrying_an_external_join_discards_messages_buffered_for_the_previous_attempt(case: TestContext) {
        let [alice, bob] = case.sessions().await;
        let conversation = case.create_conversation([&alice]).await;

        // Bob's first attempt to join never reaches the DS, so Alice never sees it.
        let (commit_guard, _first_attempt) = conversation.external_join_unmerged(&bob).await;
        let conversation = commit_guard.finish();

        // Meanwhile Alice speaks. Bob's join is pending, so he buffers her message.
        let message = conversation.guard().await.encrypt_message("hello").await.unwrap();
        let decrypted = bob
            .transaction
            .decrypt_message(conversation.id(), message)
            .await
            .unwrap();
        assert!(
            decrypted.is_empty(),
            "Bob's join is pending, so he must defer Alice's message"
        );
        assert_eq!(bob.transaction.count_entities().await.pending_messages, 1);

        // Bob tries again.
        let (commit_guard, _second_attempt) = conversation.external_join_unmerged(&bob).await;
        assert_eq!(
            bob.transaction.count_entities().await.pending_messages,
            0,
            "starting a new join attempt must discard the messages buffered for the previous one"
        );

        // This time the DS accepts Bob's commit.
        let join_commit = commit_guard.message().to_bytes().unwrap();
        let conversation = commit_guard.notify_members().await;
        let decrypted = bob
            .transaction
            .decrypt_message(conversation.id(), join_commit)
            .await
            .unwrap();
        assert_eq!(decrypted.len(), 1, "nothing buffered may be replayed");
        assert!(
            decrypted[0].is_commit(),
            "the only message must be Bob's own join commit"
        );
        assert!(conversation.is_functional_and_contains([&alice, &bob]).await);
    }
}
