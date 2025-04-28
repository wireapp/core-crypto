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
    /// If the Delivery Service accepts the external commit, you have to
    /// [PendingConversation::merge] in order to get back
    /// a functional MLS group. On the opposite, if it rejects it, you can either
    /// retry by just calling again [TransactionContext::join_by_external_commit].
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

        match pending_conversation.send_commit(commit_bundle).await {
            Ok(()) => {
                pending_conversation
                    .merge()
                    .await
                    .map_err(RecursiveError::mls_conversation("merging from external commit"))?;
            }
            Err(e @ mls::conversation::Error::MessageRejected { .. }) => {
                pending_conversation
                    .clear()
                    .await
                    .map_err(RecursiveError::mls_conversation("clearing external commit"))?;
                return Err(RecursiveError::mls_conversation("sending commit")(e).into());
            }
            Err(e) => return Err(RecursiveError::mls_conversation("sending commit")(e).into()),
        };

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
    use openmls::prelude::*;
    use wasm_bindgen_test::*;

    use core_crypto_keystore::{CryptoKeystoreError, CryptoKeystoreMls, MissingKeyErrorKind};

    use super::Error;
    use crate::{
        LeafError,
        prelude::{MlsConversationConfiguration, WelcomeBundle},
        test_utils::*,
        transaction_context,
    };

    wasm_bindgen_test_configure!(run_in_browser);

    #[apply(all_cred_cipher)]
    #[wasm_bindgen_test]
    async fn join_by_external_commit_should_succeed(case: TestContext) {
        run_test_with_client_ids(case.clone(), ["alice", "bob"], move |[alice, bob]| {
            Box::pin(async move {
                let id = conversation_id();
                alice
                    .transaction
                    .new_conversation(&id, case.credential_type, case.cfg.clone())
                    .await
                    .unwrap();

                // export Alice group info
                let group_info = alice.get_group_info(&id).await;

                // Bob tries to join Alice's group
                let (external_commit, mut pending_conversation) = bob
                    .create_unmerged_external_commit(group_info.clone(), case.custom_cfg(), case.credential_type)
                    .await;

                // Alice acks the request and adds the new member
                assert_eq!(alice.get_conversation_unchecked(&id).await.members().len(), 1);
                let decrypted = alice
                    .transaction
                    .conversation(&id)
                    .await
                    .unwrap()
                    .decrypt_message(&external_commit.commit.to_bytes().unwrap())
                    .await
                    .unwrap();
                assert_eq!(alice.get_conversation_unchecked(&id).await.members().len(), 2);

                // verify Bob's (sender) identity
                bob.verify_sender_identity(&case, &decrypted).await;

                // Let's say backend accepted our external commit.
                // So Bob can merge the commit and update the local state
                assert!(bob.transaction.conversation(&id).await.is_err());
                pending_conversation.merge().await.unwrap();
                assert!(bob.transaction.conversation(&id).await.is_ok());
                assert_eq!(bob.get_conversation_unchecked(&id).await.members().len(), 2);
                assert!(alice.try_talk_to(&id, &bob).await.is_ok());

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
                assert!(bob.try_talk_to(&id, &alice).await.is_ok());
            })
        })
        .await
    }

    #[apply(all_cred_cipher)]
    #[wasm_bindgen_test]
    async fn join_by_external_commit_should_be_retriable(case: TestContext) {
        run_test_with_client_ids(case.clone(), ["alice", "bob"], move |[alice_central, bob_central]| {
            Box::pin(async move {
                let id = conversation_id();
                alice_central
                    .transaction
                    .new_conversation(&id, case.credential_type, case.cfg.clone())
                    .await
                    .unwrap();

                // export Alice group info
                let group_info = alice_central.get_group_info(&id).await;

                // Bob tries to join Alice's group
                bob_central
                    .create_unmerged_external_commit(group_info.clone(), case.custom_cfg(), case.credential_type)
                    .await;
                // BUT for some reason the Delivery Service will reject this external commit
                // e.g. another commit arrived meanwhile and the [GroupInfo] is no longer valid
                // But bob doesn't receive the rejection message, so the commit is still pending

                // Retrying
                let WelcomeBundle {
                    id: conversation_id, ..
                } = bob_central
                    .transaction
                    .join_by_external_commit(group_info, case.custom_cfg(), case.credential_type)
                    .await
                    .unwrap();
                assert_eq!(conversation_id.as_slice(), &id);
                assert!(bob_central.transaction.conversation(&id).await.is_ok());
                assert_eq!(bob_central.get_conversation_unchecked(&id).await.members().len(), 2);

                let external_commit = bob_central.mls_transport.latest_commit().await;
                // Alice decrypts the external commit and adds Bob
                assert_eq!(alice_central.get_conversation_unchecked(&id).await.members().len(), 1);
                alice_central
                    .transaction
                    .conversation(&id)
                    .await
                    .unwrap()
                    .decrypt_message(&external_commit.to_bytes().unwrap())
                    .await
                    .unwrap();
                assert_eq!(alice_central.get_conversation_unchecked(&id).await.members().len(), 2);

                assert!(alice_central.try_talk_to(&id, &bob_central).await.is_ok());
            })
        })
        .await
    }

    #[apply(all_cred_cipher)]
    #[wasm_bindgen_test]
    async fn should_fail_when_bad_epoch(case: TestContext) {
        use crate::mls;

        run_test_with_client_ids(case.clone(), ["alice", "bob"], move |[alice_central, bob_central]| {
            Box::pin(async move {
                let id = conversation_id();
                alice_central
                    .transaction
                    .new_conversation(&id, case.credential_type, case.cfg.clone())
                    .await
                    .unwrap();

                let group_info = alice_central.get_group_info(&id).await;
                // try to make an external join into Alice's group
                bob_central
                    .transaction
                    .join_by_external_commit(group_info, case.custom_cfg(), case.credential_type)
                    .await
                    .unwrap();

                let external_commit = bob_central.mls_transport.latest_commit().await;

                // Alice creates a new commit before receiving the external join
                alice_central
                    .transaction
                    .conversation(&id)
                    .await
                    .unwrap()
                    .update_key_material()
                    .await
                    .unwrap();

                // receiving the external join with outdated epoch should fail because of
                // the wrong epoch
                let result = alice_central
                    .transaction
                    .conversation(&id)
                    .await
                    .unwrap()
                    .decrypt_message(&external_commit.to_bytes().unwrap())
                    .await;
                assert!(matches!(result.unwrap_err(), mls::conversation::Error::StaleCommit));
            })
        })
        .await
    }

    #[apply(all_cred_cipher)]
    #[wasm_bindgen_test]
    async fn existing_clients_can_join(case: TestContext) {
        run_test_with_client_ids(case.clone(), ["alice", "bob"], move |[alice_central, bob_central]| {
            Box::pin(async move {
                let id = conversation_id();
                alice_central
                    .transaction
                    .new_conversation(&id, case.credential_type, case.cfg.clone())
                    .await
                    .unwrap();
                alice_central.invite_all(&case, &id, [&bob_central]).await.unwrap();
                let group_info = alice_central.get_group_info(&id).await;
                // Alice can rejoin by external commit
                alice_central
                    .transaction
                    .join_by_external_commit(group_info.clone(), case.custom_cfg(), case.credential_type)
                    .await
                    .unwrap();
            })
        })
        .await
    }

    #[apply(all_cred_cipher)]
    #[wasm_bindgen_test]
    async fn should_fail_when_no_pending_external_commit(case: TestContext) {
        run_test_with_central(case.clone(), move |[central]| {
            Box::pin(async move {
                let non_existent_id = conversation_id();
                // try to get a non-existent pending group
                let err = central
                    .transaction
                    .pending_conversation(&non_existent_id)
                    .await
                    .unwrap_err();

                assert!(matches!(
                   err, Error::Leaf(LeafError::ConversationNotFound(id)) if non_existent_id == id
                ));
            })
        })
        .await
    }

    #[apply(all_cred_cipher)]
    #[wasm_bindgen_test]
    async fn should_return_valid_group_info(case: TestContext) {
        run_test_with_client_ids(
            case.clone(),
            ["alice", "bob", "charlie"],
            move |[alice_central, bob_central, charlie_central]| {
                Box::pin(async move {
                    let id = conversation_id();
                    alice_central
                        .transaction
                        .new_conversation(&id, case.credential_type, case.cfg.clone())
                        .await
                        .unwrap();

                    // export Alice group info
                    let group_info = alice_central.get_group_info(&id).await;

                    // Bob tries to join Alice's group
                    bob_central
                        .transaction
                        .join_by_external_commit(group_info, case.custom_cfg(), case.credential_type)
                        .await
                        .unwrap();

                    let bob_external_commit = bob_central.mls_transport.latest_commit().await;
                    assert!(bob_central.transaction.conversation(&id).await.is_ok());
                    assert_eq!(bob_central.get_conversation_unchecked(&id).await.members().len(), 2);

                    // Alice decrypts the commit, Bob's in !
                    alice_central
                        .transaction
                        .conversation(&id)
                        .await
                        .unwrap()
                        .decrypt_message(&bob_external_commit.to_bytes().unwrap())
                        .await
                        .unwrap();
                    assert_eq!(alice_central.get_conversation_unchecked(&id).await.members().len(), 2);
                    assert!(alice_central.try_talk_to(&id, &bob_central).await.is_ok());

                    // Now charlie wants to join with the [GroupInfo] from Bob's external commit
                    let group_info = bob_central.mls_transport.latest_group_info().await;
                    let bob_gi = group_info.get_group_info();
                    charlie_central
                        .transaction
                        .join_by_external_commit(bob_gi, case.custom_cfg(), case.credential_type)
                        .await
                        .unwrap();

                    let charlie_external_commit = charlie_central.mls_transport.latest_commit().await;

                    // Both Alice & Bob decrypt the commit
                    alice_central
                        .transaction
                        .conversation(&id)
                        .await
                        .unwrap()
                        .decrypt_message(charlie_external_commit.to_bytes().unwrap())
                        .await
                        .unwrap();
                    bob_central
                        .transaction
                        .conversation(&id)
                        .await
                        .unwrap()
                        .decrypt_message(charlie_external_commit.to_bytes().unwrap())
                        .await
                        .unwrap();
                    assert_eq!(alice_central.get_conversation_unchecked(&id).await.members().len(), 3);
                    assert_eq!(bob_central.get_conversation_unchecked(&id).await.members().len(), 3);

                    // Charlie is also in!
                    assert!(charlie_central.transaction.conversation(&id).await.is_ok());
                    assert_eq!(charlie_central.get_conversation_unchecked(&id).await.members().len(), 3);
                    assert!(charlie_central.try_talk_to(&id, &alice_central).await.is_ok());
                    assert!(charlie_central.try_talk_to(&id, &bob_central).await.is_ok());
                })
            },
        )
        .await
    }

    #[apply(all_cred_cipher)]
    #[wasm_bindgen_test]
    async fn clear_pending_group_should_succeed(case: TestContext) {
        run_test_with_client_ids(case.clone(), ["alice", "bob"], move |[alice_central, bob_central]| {
            Box::pin(async move {
                let id = conversation_id();
                alice_central
                    .transaction
                    .new_conversation(&id, case.credential_type, case.cfg.clone())
                    .await
                    .unwrap();

                let initial_count = alice_central.transaction.count_entities().await;

                // export Alice group info
                let group_info = alice_central.get_group_info(&id).await;

                // Bob tries to join Alice's group
                let (_, mut pending_conversation) = bob_central
                    .create_unmerged_external_commit(group_info.clone(), case.custom_cfg(), case.credential_type)
                    .await;

                // But for some reason, Bob wants to abort joining the group
                pending_conversation.clear().await.unwrap();

                let final_count = alice_central.transaction.count_entities().await;
                assert_eq!(initial_count, final_count);
            })
        })
        .await
    }

    #[apply(all_cred_cipher)]
    #[wasm_bindgen_test]
    async fn new_with_inflight_join_should_fail_when_already_exists(case: TestContext) {
        run_test_with_client_ids(case.clone(), ["alice", "bob"], move |[alice_central, bob_central]| {
            Box::pin(async move {
                let id = conversation_id();
                alice_central
                    .transaction
                    .new_conversation(&id, case.credential_type, case.cfg.clone())
                    .await
                    .unwrap();
                let gi = alice_central.get_group_info(&id).await;

                // Bob to join a conversation but while the server processes its request he
                // creates a conversation with the id of the conversation he's trying to join
                bob_central
                    .transaction
                    .join_by_external_commit(gi, case.custom_cfg(), case.credential_type)
                    .await
                    .unwrap();
                // erroneous call
                let conflict_join = bob_central
                    .transaction
                    .new_conversation(&id, case.credential_type, case.cfg.clone())
                    .await;
                assert!(matches!(
                    conflict_join.unwrap_err(),

                    Error::Leaf(LeafError::ConversationAlreadyExists(i))
                    if i == id
                ));
            })
        })
        .await
    }

    #[apply(all_cred_cipher)]
    #[wasm_bindgen_test]
    async fn new_with_inflight_welcome_should_fail_when_already_exists(case: TestContext) {
        use crate::mls;

        run_test_with_client_ids(case.clone(), ["alice", "bob"], move |[alice_central, bob_central]| {
            Box::pin(async move {
                let id = conversation_id();
                alice_central
                    .transaction
                    .new_conversation(&id, case.credential_type, case.cfg.clone())
                    .await
                    .unwrap();
                let gi = alice_central.get_group_info(&id).await;

                // While Bob tries to join a conversation via external commit he's also invited
                // to a conversation with the same id through a Welcome message
                bob_central
                    .transaction
                    .join_by_external_commit(gi, case.custom_cfg(), case.credential_type)
                    .await
                    .unwrap();

                let bob = bob_central.rand_key_package(&case).await;
                alice_central
                    .transaction
                    .conversation(&id)
                    .await
                    .unwrap()
                    .add_members(vec![bob])
                    .await
                    .unwrap();

                let welcome = alice_central.mls_transport.latest_welcome_message().await;
                // erroneous call
                let conflict_welcome = bob_central
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
        })
        .await
    }

    #[apply(all_cred_cipher)]
    #[wasm_bindgen_test]
    async fn should_fail_when_invalid_group_info(case: TestContext) {
        run_test_with_client_ids(
            case.clone(),
            ["alice", "bob", "guest"],
            move |[alice_central, bob_central, guest_central]| {
                Box::pin(async move {
                    let expiration_time = 14;
                    let start = web_time::Instant::now();
                    let id = conversation_id();
                    alice_central
                        .transaction
                        .new_conversation(&id, case.credential_type, case.cfg.clone())
                        .await
                        .unwrap();

                    let invalid_kp = bob_central.new_keypackage(&case, Lifetime::new(expiration_time)).await;
                    alice_central
                        .transaction
                        .conversation(&id)
                        .await
                        .unwrap()
                        .add_members(vec![invalid_kp.into()])
                        .await
                        .unwrap();

                    let elapsed = start.elapsed();
                    // Give time to the certificate to expire
                    let expiration_time = core::time::Duration::from_secs(expiration_time);
                    if expiration_time > elapsed {
                        async_std::task::sleep(expiration_time - elapsed + core::time::Duration::from_secs(1)).await;
                    }

                    let group_info = alice_central.get_group_info(&id).await;

                    let join_ext_commit = guest_central
                        .transaction
                        .join_by_external_commit(group_info, case.custom_cfg(), case.credential_type)
                        .await;

                    // TODO: currently succeeds as we don't anymore validate KeyPackage lifetime upon reception: find another way to craft an invalid KeyPackage. Tracking issue: WPB-9596
                    join_ext_commit.unwrap();
                    /*assert!(matches!(
                        join_ext_commit.unwrap_err(),
                        CryptoError::MlsError(MlsError::MlsExternalCommitError(ExternalCommitError::PublicGroupError(
                            CreationFromExternalError::TreeSyncError(TreeSyncFromNodesError::LeafNodeValidationError(
                                LeafNodeValidationError::Lifetime(LifetimeError::NotCurrent),
                            )),
                        )))
                    ));*/
                })
            },
        )
        .await
    }

    #[apply(all_cred_cipher)]
    #[wasm_bindgen_test]
    async fn group_should_have_right_config(case: TestContext) {
        run_test_with_client_ids(case.clone(), ["alice", "bob"], move |[alice_central, bob_central]| {
            Box::pin(async move {
                let id = conversation_id();
                alice_central
                    .transaction
                    .new_conversation(&id, case.credential_type, case.cfg.clone())
                    .await
                    .unwrap();

                let gi = alice_central.get_group_info(&id).await;
                let (_, mut pending_conversation) = bob_central
                    .create_unmerged_external_commit(gi, case.custom_cfg(), case.credential_type)
                    .await;
                pending_conversation.merge().await.unwrap();
                let group = bob_central.get_conversation_unchecked(&id).await;

                let capabilities = group.group.group_context_extensions().required_capabilities().unwrap();

                // see https://www.rfc-editor.org/rfc/rfc9420.html#section-11.1
                assert!(capabilities.extension_types().is_empty());
                assert!(capabilities.proposal_types().is_empty());
                assert_eq!(
                    capabilities.credential_types(),
                    MlsConversationConfiguration::DEFAULT_SUPPORTED_CREDENTIALS
                );
            })
        })
        .await
    }
}
