//! This module contains the implementation of [TransactionContext::join_by_external_commit].

use core_crypto_keystore::{entities::InboxMessage, traits::DeletableBySearchKey as _};
use openmls::prelude::{MlsGroup, group_info::VerifiableGroupInfo};

use super::{Error, Result};
use crate::{
    CommitBundle, ConversationConfiguration, ConversationId, CredentialRef, GroupInfoBundle, KeystoreError,
    OpenMlsError, RecursiveError,
    mls::{
        self,
        conversation::{ConversationIdRef, ConversationMut},
    },
    transaction_context::TransactionContext,
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
    /// **Rejoining an existing conversation overwrites it as soon as anything here reaches the
    /// keystore.** A pending join shares its row with any established conversation of the same id,
    /// rather than a separate one, so retrying after a failure (which persists the attempt within
    /// the current transaction, to make the retry possible) leaves the previous conversation's
    /// state unrecoverable even if this call, or the retry, never succeeds. Note that every path
    /// which saves the attempt also returns an error, so whether the saved row survives is up to
    /// the caller: by default an error crossing the FFI aborts the transaction and rolls it back. This is fine because
    /// the only reason to call this on a conversation you already have is that its local state is already
    /// considered unusable — that is what "rejoin" means here — so there is nothing worth preserving in the row it
    /// replaces.
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
        // savepoint here: creating external join commit may overwrite an existing conversation, but we need to be able
        // to roll that back
        let mut pending_conversation = inner
            .with_savepoint(
                "create_external_join_commit",
                async || {
                    let (commit_bundle, pending_conversation) =
                        self.create_external_join_commit(group_info, credential_ref).await?;
                    let transport = self.mls_transport().await?;
                    // We want to rollback on exactly one outcome of sending the commit bundle: an explicit rejection.
                    // Everything else gets propagated, because it allows for the possibility that the DS received
                    // the commit bundle and then the response got lost.
                    //
                    // However, as we don't know ahead of time where in the error chain that rejection
                    // woudld be reported, we have to just walk the whole chain.
                    let outcome = transport
                        .send_commit_bundle(commit_bundle)
                        .await
                        .map(|()| pending_conversation)
                        .map_err(RecursiveError::context(
                            "sending commit bundle for external join commit",
                        ))
                        .map_err(Into::into);
                    if let Err(outcome_err) = &outcome {
                        let mut err: &dyn std::error::Error = outcome_err;
                        let was_rejected = loop {
                            if let Some(err) = err.downcast_ref()
                                && matches!(err, mls::conversation::Error::MessageRejected { .. })
                            {
                                break true;
                            }
                            let Some(inner) = err.source() else {
                                break false;
                            };
                            err = inner;
                        };
                        if was_rejected {
                            // outcome is definitely an error in this branch, so this will never trigger,
                            // but this map is necessary for the types to work out.
                            return outcome.map(Ok);
                        }
                    }
                    // We already checked if the outcome was a rejection, so now we can just Ok-wrap it
                    // so that nothing else causes a savepoint rollback. This ensures we have the capability
                    // to restore it later if the DS did receive it and then later delivers it to us.
                    Ok(outcome)
                },
                Error::savepoint,
            )
            .await??;

        // savepoint here: if merge fails, rollback recovers pending state for recovery
        inner
            .with_savepoint(
                "merge_pending_commit",
                async || {
                    pending_conversation
                        .merge_commit()
                        .await
                        .map_err(RecursiveError::context("merging pending commit"))
                        .map_err(Into::into)
                },
                Error::savepoint,
            )
            .await?;

        Ok(pending_conversation.id().to_owned())
    }

    /// Create an external join commit, persisting the pending conversation.
    async fn create_external_join_commit(
        &self,
        group_info: VerifiableGroupInfo,
        credential_ref: &CredentialRef,
    ) -> Result<(CommitBundle, ConversationMut)> {
        let inner = self.inner()?;
        let cipher_suite = group_info.ciphersuite().into();
        let mls_provider = self.crypto_provider().await?;
        let credential = credential_ref
            .load(&inner.transaction)
            .await
            .map_err(RecursiveError::context("loading credential"))?;

        let configuration = ConversationConfiguration {
            cipher_suite,
            ..Default::default()
        };

        let id = ConversationIdRef::new(group_info.group_id().as_slice()).to_owned();
        if self.conversation_exists(&id, Some(false)).await? {
            // rejoining replaces the group without going through `mutate_group`, so we have to
            // capture epoch data from an existing group here
            let conversation = self.conversation(&id).await?;
            conversation
                .record_epoch_data(conversation.group().await.mls_group())
                .await
                .map_err(RecursiveError::context("recording epoch data before rejoin"))?;
        }

        let (group, commit, group_info) = MlsGroup::join_by_external_commit(
            &mls_provider,
            &credential.signature_key_pair,
            None,
            group_info,
            &configuration
                .as_openmls_default_configuration()
                .map_err(RecursiveError::context(
                    "using configuration as openmls default configuration",
                ))?,
            &[],
            credential.to_mls_credential_with_key(),
        )
        .await
        .map_err(OpenMlsError::wrap("joining mls group by external commit"))?;

        // We should always have ratchet tree extension turned on hence GroupInfo should always be present
        let group_info = group_info
            .ok_or(mls::conversation::Error::MissingGroupInfo)
            .map_err(RecursiveError::context("retrieving group info"))?;
        let group_info = GroupInfoBundle::try_new_full_plaintext(group_info)
            .map_err(RecursiveError::context("trying new full plaintext group info bundle"))?;

        let pending_conversation = self
            .persist_conversation_from_mls_group(group, configuration, true)
            .await
            .map_err(RecursiveError::context("creating pending conversation"))?;

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

        let commit_bundle = CommitBundle {
            welcome: None,
            commit,
            group_info,
            encrypted_message: None,
        };

        Ok((commit_bundle, pending_conversation))
    }

    /// Exactly as [`Self::create_external_join_commit`], but crate-public for testing
    #[cfg(test)]
    pub(crate) async fn create_external_join_commit_test(
        &self,
        group_info: VerifiableGroupInfo,
        credential_ref: &CredentialRef,
    ) -> Result<(CommitBundle, ConversationMut)> {
        self.create_external_join_commit(group_info, credential_ref).await
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Weak};

    use async_lock::Mutex;
    use core_crypto_keystore::{entities::PersistedMlsGroup, traits::FetchFromDatabase as _};

    use crate::{
        CommitBundle, ConversationConfiguration, CoreCrypto, DecryptedMessage, DecryptionOutcome, DeferralReason,
        HistorySecret, MlsTransport, RejectionReason, TransportData, test_utils::*, transaction_context::Error,
    };

    #[derive(Debug, Default)]
    struct TransportWithLostCommitResponse {
        sent_bundle: Mutex<Option<CommitBundle>>,
    }

    #[cfg_attr(target_os = "unknown", async_trait::async_trait(?Send))]
    #[cfg_attr(not(target_os = "unknown"), async_trait::async_trait)]
    impl MlsTransport for TransportWithLostCommitResponse {
        async fn send_commit_bundle(&self, commit_bundle: CommitBundle) -> crate::Result<()> {
            let replaced = self.sent_bundle.lock().await.replace(commit_bundle);
            assert!(replaced.is_none(), "this provider only tests sending a single bundle");
            Err(crate::Error::ErrorDuringMlsTransport("commit response lost".into()))
        }

        async fn prepare_for_transport(&self, _secret: &HistorySecret) -> crate::Result<TransportData> {
            unreachable!("this test transport only sends commits")
        }
    }

    #[cfg_attr(target_os = "unknown", async_trait::async_trait(?Send))]
    #[cfg_attr(not(target_os = "unknown"), async_trait::async_trait)]
    impl MlsTransportTestExt for TransportWithLostCommitResponse {
        async fn latest_commit_bundle(&self) -> CommitBundle {
            self.sent_bundle.lock().await.clone().expect("a commit was sent")
        }
    }

    #[macro_rules_attribute::apply(smol_macros::test)]
    async fn external_join_can_complete_after_a_lost_commit_response() {
        let case = TestContext::default();
        let [alice, mut bob] = case.sessions().await;
        let conversation = case.create_conversation([&alice]).await;
        let id = conversation.id().clone();
        let group_info = conversation.export_group_info().await;
        let transport = Arc::new(TransportWithLostCommitResponse::default());
        bob.replace_transport(transport.clone()).await;

        let err = bob
            .transaction
            .join_by_external_commit(group_info, &bob.initial_credential)
            .await
            .unwrap_err();
        assert!(innermost_source_matches!(
            err,
            crate::Error::ErrorDuringMlsTransport(message) if message == "commit response lost"
        ));
        let join_commit = transport.latest_commit().await.to_bytes().unwrap();

        // The commit reached the delivery service even though Bob missed its response.
        let outcome = alice
            .transaction
            .decrypt_message(&id, join_commit.clone())
            .await
            .unwrap();
        assert!(outcome.into_single_decrypted().is_commit());

        // Bob handles the send error and commits his transaction before receiving his own join commit.
        bob.commit_transaction().await;
        let pending = bob
            .transaction
            .database()
            .unwrap()
            .get_borrowed::<PersistedMlsGroup>(id.as_ref().keystore())
            .await
            .unwrap()
            .expect("a lost commit response must leave the pending join in the database");
        assert!(pending.is_pending);

        let outcome = bob.transaction.decrypt_message(&id, join_commit).await.unwrap();
        assert!(outcome.into_single_decrypted().is_commit());
        assert_eq!(
            bob.transaction.conversation(&id).await.unwrap().epoch().await,
            conversation.guard().await.epoch().await
        );
    }

    #[derive(Debug)]
    struct TransportThatClearsPkiEnvironment {
        core_crypto: Weak<CoreCrypto>,
        sent_bundle: Mutex<Option<CommitBundle>>,
    }

    #[cfg_attr(target_os = "unknown", async_trait::async_trait(?Send))]
    #[cfg_attr(not(target_os = "unknown"), async_trait::async_trait)]
    impl MlsTransport for TransportThatClearsPkiEnvironment {
        async fn send_commit_bundle(&self, commit_bundle: CommitBundle) -> crate::Result<()> {
            *self.sent_bundle.lock().await = Some(commit_bundle);
            self.core_crypto.upgrade().unwrap().set_pki_environment(None).await;
            Ok(())
        }

        async fn prepare_for_transport(&self, _secret: &HistorySecret) -> crate::Result<TransportData> {
            unreachable!("this test transport only sends commits")
        }
    }

    #[cfg_attr(target_os = "unknown", async_trait::async_trait(?Send))]
    #[cfg_attr(not(target_os = "unknown"), async_trait::async_trait)]
    impl MlsTransportTestExt for TransportThatClearsPkiEnvironment {
        async fn latest_commit_bundle(&self) -> CommitBundle {
            self.sent_bundle.lock().await.clone().expect("a commit was sent")
        }
    }

    /// We want to ensure that any rollback during external join restores the pending epoch in both
    /// the DB and the cache, and can succeed later once the problem is resolved.
    ///
    /// We accomplish that by temporarily disabling the PKI environment. That particular error is
    /// unlikely to be the actual cause of a rollback, but it lets us temporarily induce a failure
    /// in the right place.
    #[macro_rules_attribute::apply(smol_macros::test)]
    async fn failed_external_join_merge_leaves_the_conversation_pending() {
        let case = TestContext::default_x509();
        let [alice, bob] = case.sessions().await;
        let conversation = case.create_conversation([&alice]).await;
        let id = conversation.id();
        let epoch_before_join = conversation.guard().await.epoch().await;
        let group_info = conversation.export_group_info().await;
        let core_crypto = bob.core_crypto();
        let pki_environment = core_crypto.get_pki_environment().await.unwrap();

        // The transport accepts the commit and removes the PKI environment before the local merge.
        bob.replace_transport(Arc::new(TransportThatClearsPkiEnvironment {
            core_crypto: Arc::downgrade(&core_crypto),
            sent_bundle: Mutex::new(None),
        }))
        .await;
        let error = bob
            .transaction
            .join_by_external_commit(group_info, &bob.initial_credential)
            .await
            .unwrap_err();
        assert!(innermost_source_matches!(
            error,
            crate::mls::credential::Error::MissingPKIEnvironment
        ));

        let persisted = bob
            .database()
            .get_borrowed::<PersistedMlsGroup>(id.as_ref().keystore())
            .await
            .unwrap()
            .expect("the pending join must survive a failed merge");
        assert!(persisted.is_pending);
        assert_eq!(persisted.epoch, epoch_before_join);

        let cached = bob
            .transaction
            .conversation_regardless_of_pending_status(id)
            .await
            .unwrap();
        {
            let group = cached.group().await;
            assert!(group.is_pending);
            assert_eq!(group.epoch().as_u64(), epoch_before_join);
            assert!(group.pending_commit().is_some());
        }

        core_crypto.set_pki_environment(Some(pki_environment)).await;
        let join_commit = bob.mls_transport().await.latest_commit().await.to_bytes().unwrap();
        let outcome = bob.transaction.decrypt_message(id, join_commit).await.unwrap();
        assert!(outcome.into_single_decrypted().is_commit());
        assert_eq!(
            bob.transaction.conversation(id).await.unwrap().epoch().await,
            epoch_before_join + 1
        );
    }

    #[apply(all_cred_cipher)]
    async fn join_by_external_commit_should_succeed(case: TestContext) {
        let [alice, bob] = case.sessions().await;
        Box::pin(async move {
            let conversation = case.create_conversation([&alice]).await;
            let id = conversation.id().clone();

            // Bob tries to join Alice's group
            let external_commit = conversation.external_join_unmerged(&bob).await;

            // Alice acks the request and adds the new member
            assert_eq!(external_commit.conversation().member_count().await, 1);
            let (external_commit, result) = external_commit.notify_member_fallible(&alice).await;
            assert_eq!(external_commit.conversation().members_counted_by(&alice).await, 2);

            let decrypted = result.unwrap().into_single_decrypted();
            // verify Bob's (sender) identity
            bob.verify_sender_identity(&case, &bob.initial_credential, &decrypted)
                .await;

            // Let's say backend accepted our external commit.
            // So Bob can merge the commit and update the local state
            assert!(bob.transaction.conversation(&id).await.is_err());
            bob.transaction
                .conversation_regardless_of_pending_status(&id)
                .await
                .unwrap()
                .merge_commit()
                .await
                .unwrap();
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
            let commit_guard = conversation.external_join_unmerged(&bob).await;

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
    async fn should_reject_when_bad_epoch(case: TestContext) {
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
            assert!(matches!(
                result.unwrap().into_single_rejected(),
                RejectionReason::StaleCommit
            ));
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
    async fn wiping_a_pending_join_removes_the_group(case: TestContext) {
        let [alice, bob] = case.sessions().await;
        Box::pin(async move {
            let conversation = case.create_conversation([&alice]).await;

            let commit_guard = conversation.external_join_unmerged(&bob).await;
            let conversation = commit_guard.finish();
            assert_eq!(bob.transaction.count_entities().await.pending_group, 1);

            // But for some reason, Bob wants to abort joining the group
            bob.transaction
                .conversation_regardless_of_pending_status(conversation.id())
                .await
                .unwrap()
                .wipe()
                .await
                .unwrap();

            assert_eq!(bob.transaction.count_entities().await.pending_group, 0);
            assert!(
                !bob.transaction
                    .conversation_exists(conversation.id(), None)
                    .await
                    .unwrap()
            );
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
                            &mls_provider,
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
            crate::OpenMlsErrorKind::MlsExternalCommitError(openmls::prelude::ExternalCommitError::MissingRatchetTree),
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

            let capabilities = group.group_context_extensions().required_capabilities().unwrap();

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

    #[macro_rules_attribute::apply(smol_macros::test)]
    async fn rejected_rejoin_preserves_the_conversation_and_its_inbox() {
        let mut case = TestContext::default();
        let [alice, bob, delivery_service] = case.sessions().await;
        // A non-default external sender lets us check that rollback restores the configuration too.
        let conversation = case
            .create_conversation_with_external_sender(&delivery_service, [&alice, &bob])
            .await;
        let id = conversation.id().clone();
        let established = alice.transaction.conversation(&id).await.unwrap();
        let established_epoch = established.epoch().await;
        let external_senders = established.configuration().await.external_senders.clone();
        assert_eq!(external_senders.len(), 1);

        // Alice misses Bob's update and buffers the application message he sends after it.
        let update = conversation.acting_as(&bob).await.update().await;
        let update_bytes = update.message().to_bytes().unwrap();
        let message = update
            .conversation()
            .guard()
            .await
            .encrypt_message("buffered")
            .await
            .unwrap();
        let conversation = update.finish().acting_as(&bob).await;
        let outcome = alice.transaction.decrypt_message(&id, message).await.unwrap();
        assert!(matches!(
            outcome.into_single_deferred(),
            DeferralReason::FutureEpoch { .. }
        ));

        alice
            .replace_transport(Arc::new(CoreCryptoTransportAbortProvider))
            .await;
        let error = alice
            .transaction
            .join_by_external_commit(conversation.export_group_info().await, &alice.initial_credential)
            .await
            .unwrap_err();
        assert!(innermost_source_matches!(
            error,
            crate::mls::conversation::Error::MessageRejected { .. }
        ));

        let restored = alice.transaction.conversation(&id).await.unwrap();
        assert_eq!(restored.epoch().await, established_epoch);
        assert_eq!(
            restored.configuration().await.external_senders,
            external_senders,
            "a rejected rejoin must preserve the established conversation's external senders"
        );
        let outcomes = alice.transaction.decrypt_message(&id, update_bytes).await.unwrap();
        let plaintexts = outcomes
            .into_iter()
            .filter_map(|outcome| match outcome {
                DecryptionOutcome::Decrypted(DecryptedMessage::ApplicationMessage(message)) => Some(message.plaintext),
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(plaintexts, [b"buffered".to_vec()]);
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
            matches!(decrypted.into_single_deferred(), DeferralReason::FutureEpoch { .. }),
            "Alice can't decrypt Bob's message without his commit"
        );
        assert_eq!(alice.transaction.count_entities().await.pending_messages, 1);

        // Alice gives up on her desynchronized state and rejoins. The DS hasn't confirmed her join yet.
        let commit_guard = conversation.acting_as(&bob).await.external_join_unmerged(&alice).await;
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
            matches!(decrypted.into_single_deferred(), DeferralReason::PendingJoin),
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
            matches!(
                decrypted.next(),
                Some(DecryptionOutcome::Decrypted(DecryptedMessage::Commit(_)))
            ),
            "the first message must be Alice's own join commit"
        );
        let replayed = decrypted
            .map(|outcome| outcome.into_decrypted().into_application_message().unwrap().plaintext)
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
        let commit_guard = conversation.external_join_unmerged(&bob).await;
        let conversation = commit_guard.finish();

        // Meanwhile Alice speaks. Bob's join is pending, so he buffers her message.
        let message = conversation.guard().await.encrypt_message("hello").await.unwrap();
        let decrypted = bob
            .transaction
            .decrypt_message(conversation.id(), message)
            .await
            .unwrap();
        assert!(
            matches!(decrypted.into_single_deferred(), DeferralReason::PendingJoin),
            "Bob's join is pending, so he must defer Alice's message"
        );
        assert_eq!(bob.transaction.count_entities().await.pending_messages, 1);

        // Bob tries again.
        let commit_guard = conversation.external_join_unmerged(&bob).await;
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
            matches!(decrypted[0], DecryptionOutcome::Decrypted(DecryptedMessage::Commit(_))),
            "the only message must be Bob's own join commit"
        );
        assert!(conversation.is_functional_and_contains([&alice, &bob]).await);
    }

    /// Abandoning an external join abandons the messages buffered while it was pending.
    #[apply(all_cred_cipher)]
    async fn abandoning_an_external_join_abandons_buffered_messages(case: TestContext) {
        let [alice, mut bob] = case.sessions().await;
        Box::pin(async move {
            let conversation = case.create_conversation([&alice]).await;

            // Bob asks to join Alice's group with an external commit, and waits for the DS to accept it.
            let commit_guard = conversation.external_join_unmerged(&bob).await;
            let conversation = commit_guard.finish();

            // While Bob waits, Alice speaks. Bob can process nothing until his own join is merged, so he
            // buffers her message to replay afterwards.
            let app_msg = conversation
                .guard()
                .await
                .encrypt_message(b"Hello Bob !")
                .await
                .unwrap();
            assert!(
                matches!(
                    bob.transaction.conversation(conversation.id()).await.unwrap_err(),
                    Error::PendingConversation(_)
                ),
                "Bob should not have the conversation yet"
            );
            let decrypted = bob
                .transaction
                .conversation_regardless_of_pending_status(conversation.id())
                .await
                .unwrap()
                .decrypt_message(app_msg)
                .await
                .unwrap();
            assert!(
                matches!(decrypted.into_single_deferred(), DeferralReason::PendingJoin),
                "Alice's message must have been deferred"
            );

            let counts = bob.transaction.count_entities().await;
            assert_eq!(counts.pending_group, 1, "Bob's join is still pending");
            assert_eq!(counts.pending_messages, 1, "Alice's message must have been buffered");

            // The DS rejects Bob's commit, so he gives up on the join.
            bob.transaction
                .conversation_regardless_of_pending_status(conversation.id())
                .await
                .unwrap()
                .wipe()
                .await
                .unwrap();

            drop(conversation);
            bob.commit_transaction().await;

            let counts = bob.transaction.count_entities().await;
            assert_eq!(
                counts.pending_group, 0,
                "abandoning the join must have removed the pending group"
            );
            assert_eq!(
                counts.pending_messages, 0,
                "the buffered message belongs to a pending conversation which was abandoned, so abandoning \
                 it must have taken the message with it"
            );
        })
        .await
    }

    #[apply(all_cred_cipher)]
    async fn should_buffer_and_reapply_messages_after_external_commit_merged(case: TestContext) {
        let [alice, bob, charlie, debbie] = case.sessions().await;
        Box::pin(async move {
            let conversation = case.create_conversation([&alice, &debbie]).await;
            // Bob tries to join Alice's group with an external commit
            let commit_guard = conversation.external_join_unmerged(&bob).await;
            let external_commit = commit_guard.message();

            // Alice decrypts the external commit...
            let conversation = commit_guard
                .notify_member(&alice)
                .await
                .process_member_changes()
                .await
                .finish();

            // ...then Alice generates new messages for this epoch
            let app_msg = conversation
                .guard()
                .await
                .encrypt_message(b"Hello Bob !")
                .await
                .unwrap();

            // And proposes to remove debbie
            let proposal_guard = conversation.remove_proposal(&debbie).await;
            let remove_proposal = proposal_guard.message();

            let conversation = proposal_guard.finish();

            let commit_guard = conversation.invite([&charlie]).await;
            let commit = commit_guard.message();
            let conversation = commit_guard.process_member_changes().await.finish();

            // And now Bob will have to decrypt those messages while he hasn't yet merged its external commit
            // To add more fun, he will buffer the messages in exactly the wrong order (to make
            // sure he reapplies them in the right order afterwards)
            assert!(
                matches!(
                    bob.transaction.conversation(conversation.id()).await.unwrap_err(),
                    Error::PendingConversation(_)
                ),
                "Bob should not have the conversation yet"
            );
            let mut bob_conversation = bob
                .transaction
                .conversation_regardless_of_pending_status(conversation.id())
                .await
                .unwrap();
            let messages = [remove_proposal, commit].map(|m| m.to_bytes().unwrap());
            for message in messages.into_iter().chain([app_msg]) {
                let decrypted = bob_conversation.decrypt_message(message).await.unwrap();
                assert!(
                    matches!(decrypted.into_single_deferred(), DeferralReason::PendingJoin),
                    "the message must have been deferred"
                );
            }

            // Bob should have buffered the messages
            assert_eq!(bob.transaction.count_entities().await.pending_messages, 3);

            let observer = TestEpochObserver::new();
            bob.session()
                .await
                .register_epoch_observer(observer.clone())
                .await
                .unwrap();

            // Finally, Bob receives the green light from the DS and he can merge the external commit
            let mut decrypted = bob_conversation
                .decrypt_message(external_commit.to_bytes().unwrap())
                .await
                .unwrap()
                .into_iter();
            assert!(
                matches!(
                    decrypted.next(),
                    Some(DecryptionOutcome::Decrypted(DecryptedMessage::Commit(_)))
                ),
                "the first message must be Bob's own join commit"
            );
            assert!(
                !bob_conversation.group().await.is_pending,
                "merging the join commit must have made the conversation established"
            );

            let restored = decrypted.map(DecryptionOutcomeExt::into_decrypted).collect::<Vec<_>>();
            assert_eq!(restored.len(), 3, "all buffered messages must have been restored");
            let plaintexts = restored
                .iter()
                .filter_map(|message| message.as_application_message())
                .map(|message| message.plaintext.as_slice())
                .collect::<Vec<_>>();
            assert_eq!(plaintexts, [b"Hello Bob !".as_slice()]);
            assert_eq!(restored.iter().filter(|message| message.is_proposal()).count(), 1);
            assert_eq!(restored.iter().filter(|message| message.is_commit()).count(), 1);

            assert_eq!(conversation.member_count().await, 3);
            assert!(conversation.is_functional().await);
            assert!(conversation.is_functional_and_contains([&alice, &bob, &charlie]).await);

            // After merging we should erase all those pending messages
            assert_eq!(bob.transaction.count_entities().await.pending_messages, 0);

            let final_epoch = bob_conversation.epoch().await;
            drop(bob_conversation);
            bob.transaction.finish().await.unwrap();

            // Bob's conversation advanced twice: once when his join commit was merged,
            // and once more when Alice's commit adding Charlie was restored.
            let observed_epochs = observer.observed_epochs().await;
            let expected_epochs = [final_epoch - 1, final_epoch].map(|epoch| (conversation.id().clone(), epoch));
            assert_eq!(observed_epochs, expected_epochs);
        })
        .await
    }

    #[apply(all_cred_cipher)]
    async fn should_not_reapply_buffered_messages_when_rejoining(case: TestContext) {
        let [alice, bob] = case.sessions().await;
        Box::pin(async move {
            let conversation = case.create_conversation([&alice, &bob]).await;

            // Alice will never see this commit
            let conversation = conversation.acting_as(&bob).await;
            let commit_guard = conversation.update().await;
            let conversation = commit_guard.conversation();

            let msg1 = conversation.guard().await.encrypt_message("A").await.unwrap();
            let msg2 = conversation.guard().await.encrypt_message("B").await.unwrap();

            let conversation = commit_guard.finish();
            // Since Alice missed Bob's commit she should buffer this message
            let decrypt = conversation.guard().await.decrypt_message(msg1).await;
            assert!(
                matches!(
                    decrypt.unwrap().into_single_deferred(),
                    DeferralReason::FutureEpoch { .. }
                ),
                "the message must have been deferred"
            );
            let decrypt = conversation.guard().await.decrypt_message(msg2).await;
            assert!(
                matches!(
                    decrypt.unwrap().into_single_deferred(),
                    DeferralReason::FutureEpoch { .. }
                ),
                "the message must have been deferred"
            );
            assert_eq!(alice.transaction.count_entities().await.pending_messages, 2);

            let conversation = conversation.acting_as(&bob).await.external_join_notify(&alice).await;
            // Alice should have deleted all her buffered messages
            assert_eq!(alice.transaction.count_entities().await.pending_messages, 0);
            assert!(conversation.is_functional_and_contains([&alice, &bob]).await);
        })
        .await
    }
}
