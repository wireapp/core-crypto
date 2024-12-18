// Wire
// Copyright (C) 2022 Wire Swiss GmbH

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with this program. If not, see http://www.gnu.org/licenses/.

use openmls::prelude::{group_info::VerifiableGroupInfo, MlsGroup, MlsMessageOut};
use openmls_traits::OpenMlsCryptoProvider;
use tls_codec::Serialize;

use core_crypto_keystore::{
    connection::FetchFromDatabase,
    entities::{MlsPendingMessage, PersistedMlsPendingGroup},
    CryptoKeystoreMls,
};

use crate::{
    e2e_identity::init_certificates::NewCrlDistributionPoint,
    mls::credential::crl::{extract_crl_uris_from_group, get_new_crl_distribution_points},
    prelude::{
        decrypt::MlsBufferedConversationDecryptMessage, ConversationId, CryptoError, CryptoResult, MlsCiphersuite,
        MlsConversation, MlsConversationConfiguration, MlsCredentialType, MlsCustomConfiguration, MlsError,
        MlsGroupInfoBundle,
    },
};

use crate::context::CentralContext;

/// Returned when a commit is created
#[derive(Debug)]
pub struct MlsConversationInitBundle {
    /// Identifier of the conversation joined by external commit
    pub conversation_id: ConversationId,
    /// The external commit message
    pub commit: MlsMessageOut,
    /// `GroupInfo` which becomes valid when the external commit is accepted by the Delivery Service
    pub group_info: MlsGroupInfoBundle,
    /// New CRL distribution points that appeared by the introduction of a new credential
    pub crl_new_distribution_points: NewCrlDistributionPoint,
}

impl MlsConversationInitBundle {
    /// Serializes both wrapped objects into TLS and return them as a tuple of byte arrays.
    /// 0 -> external commit
    /// 1 -> public group state
    #[allow(clippy::type_complexity)]
    pub fn to_bytes(self) -> CryptoResult<(Vec<u8>, MlsGroupInfoBundle, NewCrlDistributionPoint)> {
        let commit = self.commit.tls_serialize_detached().map_err(MlsError::from)?;
        Ok((commit, self.group_info, self.crl_new_distribution_points))
    }
}

impl CentralContext {
    /// Issues an external commit and stores the group in a temporary table. This method is
    /// intended for example when a new client wants to join the user's existing groups.
    /// On success this function will return the group id and a message to be fanned out to other
    /// clients.
    ///
    /// If the Delivery Service accepts the external commit, you have to [CentralContext::merge_pending_group_from_external_commit]
    /// in order to get back a functional MLS group. On the opposite, if it rejects it, you can either
    /// retry by just calling again [CentralContext::join_by_external_commit], no need to [CentralContext::clear_pending_group_from_external_commit].
    /// If you want to abort the operation (too many retries or the user decided to abort), you can use
    /// [CentralContext::clear_pending_group_from_external_commit] in order not to bloat the user's storage but nothing
    /// bad can happen if you forget to except some storage space wasted.
    ///
    /// # Arguments
    /// * `group_info` - a GroupInfo wrapped in a MLS message. it can be obtained by deserializing a TLS serialized `GroupInfo` object
    /// * `custom_cfg` - configuration of the MLS conversation fetched from the Delivery Service
    /// * `credential_type` - kind of [openmls::prelude::Credential] to use for joining this group.
    ///   If [MlsCredentialType::Basic] is chosen and no Credential has been created yet for it,
    ///   a new one will be generated. When [MlsCredentialType::X509] is chosen, it fails when no
    ///   [openmls::prelude::Credential] has been created for the given Ciphersuite.
    ///
    /// # Return type
    /// It will return a tuple with the group/conversation id and the message containing the
    /// commit that was generated by this call
    ///
    /// # Errors
    /// Errors resulting from OpenMls, the KeyStore calls and serialization
    pub async fn join_by_external_commit(
        &self,
        group_info: VerifiableGroupInfo,
        custom_cfg: MlsCustomConfiguration,
        credential_type: MlsCredentialType,
    ) -> CryptoResult<MlsConversationInitBundle> {
        let client = &self.mls_client().await?;

        let cs: MlsCiphersuite = group_info.ciphersuite().into();
        let mls_provider = self.mls_provider().await?;
        let cb = client
            .get_most_recent_or_create_credential_bundle(&mls_provider, cs.signature_algorithm(), credential_type)
            .await?;

        let serialized_cfg = serde_json::to_vec(&custom_cfg).map_err(MlsError::MlsKeystoreSerializationError)?;

        let configuration = MlsConversationConfiguration {
            ciphersuite: cs,
            custom: custom_cfg,
            ..Default::default()
        };

        let (group, commit, group_info) = MlsGroup::join_by_external_commit(
            &mls_provider,
            &cb.signature_key,
            None,
            group_info,
            &configuration.as_openmls_default_configuration()?,
            &[],
            cb.to_mls_credential_with_key(),
        )
        .await
        .map_err(MlsError::from)?;

        // We should always have ratchet tree extension turned on hence GroupInfo should always be present
        let group_info = group_info.ok_or(CryptoError::ImplementationError)?;
        let group_info = MlsGroupInfoBundle::try_new_full_plaintext(group_info)?;

        let crl_new_distribution_points =
            get_new_crl_distribution_points(&mls_provider, extract_crl_uris_from_group(&group)?).await?;

        mls_provider
            .key_store()
            .mls_pending_groups_save(
                group.group_id().as_slice(),
                &core_crypto_keystore::ser(&group)?,
                &serialized_cfg,
                None,
            )
            .await?;

        Ok(MlsConversationInitBundle {
            conversation_id: group.group_id().to_vec(),
            commit,
            group_info,
            crl_new_distribution_points,
        })
    }

    /// This merges the commit generated by [CentralContext::join_by_external_commit], persists the group permanently and
    /// deletes the temporary one. After merging, the group should be fully functional.
    ///
    /// # Arguments
    /// * `id` - the conversation id
    ///
    /// # Errors
    /// Errors resulting from OpenMls, the KeyStore calls and deserialization
    #[cfg_attr(test, crate::dispotent)]
    pub async fn merge_pending_group_from_external_commit(
        &self,
        id: &ConversationId,
    ) -> CryptoResult<Option<Vec<MlsBufferedConversationDecryptMessage>>> {
        // Retrieve the pending MLS group from the keystore
        let mls_provider = self.mls_provider().await?;
        let (group, cfg) = mls_provider.key_store().mls_pending_groups_load(id).await?;

        let mut mls_group = core_crypto_keystore::deser::<MlsGroup>(&group)?;

        // Merge it aka bring the MLS group to life and make it usable
        mls_group
            .merge_pending_commit(&mls_provider)
            .await
            .map_err(MlsError::from)?;

        // Restore the custom configuration and build a conversation from it
        let custom_cfg = serde_json::from_slice(&cfg).map_err(MlsError::MlsKeystoreSerializationError)?;
        let configuration = MlsConversationConfiguration {
            ciphersuite: mls_group.ciphersuite().into(),
            custom: custom_cfg,
            ..Default::default()
        };

        let is_rejoin = mls_provider.key_store().mls_group_exists(id.as_slice()).await;

        // Persist the now usable MLS group in the keystore
        let mut conversation = MlsConversation::from_mls_group(mls_group, configuration, &mls_provider).await?;

        let pending_messages = self.restore_pending_messages(&mut conversation, is_rejoin).await?;

        self.mls_groups().await?.insert(id.clone(), conversation);

        // cleanup the pending group we no longer need
        mls_provider.key_store().mls_pending_groups_delete(id).await?;

        if pending_messages.is_some() {
            mls_provider.key_store().remove::<MlsPendingMessage, _>(id).await?;
        }

        Ok(pending_messages)
    }

    /// In case the external commit generated by [CentralContext::join_by_external_commit] is rejected by the Delivery Service
    /// and we want to abort this external commit once for all, we can wipe out the pending group from
    /// the keystore in order not to waste space
    ///
    /// # Arguments
    /// * `id` - the conversation id
    ///
    /// # Errors
    /// Errors resulting from the KeyStore calls
    #[cfg_attr(test, crate::dispotent)]
    pub async fn clear_pending_group_from_external_commit(&self, id: &ConversationId) -> CryptoResult<()> {
        Ok(self.keystore().await?.mls_pending_groups_delete(id).await?)
    }

    pub(crate) async fn pending_group_exists(&self, id: &ConversationId) -> CryptoResult<bool> {
        Ok(self
            .keystore()
            .await?
            .find::<PersistedMlsPendingGroup>(id.as_slice())
            .await
            .ok()
            .flatten()
            .is_some())
    }
}

#[cfg(test)]
mod tests {
    use openmls::prelude::*;
    use wasm_bindgen_test::*;

    use core_crypto_keystore::{CryptoKeystoreError, CryptoKeystoreMls, MissingKeyErrorKind};

    use crate::prelude::MlsConversationConfiguration;
    use crate::{prelude::MlsConversationInitBundle, test_utils::*, CryptoError};

    wasm_bindgen_test_configure!(run_in_browser);

    #[apply(all_cred_cipher)]
    #[wasm_bindgen_test]
    async fn join_by_external_commit_should_succeed(case: TestCase) {
        run_test_with_client_ids(
            case.clone(),
            ["alice", "bob"],
            move |[alice_central, mut bob_central]| {
                Box::pin(async move {
                    let id = conversation_id();
                    alice_central
                        .context
                        .new_conversation(&id, case.credential_type, case.cfg.clone())
                        .await
                        .unwrap();

                    // export Alice group info
                    let group_info = alice_central.get_group_info(&id).await;

                    // Bob tries to join Alice's group
                    let MlsConversationInitBundle {
                        conversation_id: group_id,
                        commit: external_commit,
                        ..
                    } = bob_central
                        .context
                        .join_by_external_commit(group_info, case.custom_cfg(), case.credential_type)
                        .await
                        .unwrap();
                    assert_eq!(group_id.as_slice(), &id);

                    // Alice acks the request and adds the new member
                    assert_eq!(alice_central.get_conversation_unchecked(&id).await.members().len(), 1);
                    let decrypted = alice_central
                        .context
                        .decrypt_message(&id, &external_commit.to_bytes().unwrap())
                        .await
                        .unwrap();
                    assert_eq!(alice_central.get_conversation_unchecked(&id).await.members().len(), 2);

                    // verify Bob's (sender) identity
                    bob_central.verify_sender_identity(&case, &decrypted).await;

                    // Let's say backend accepted our external commit.
                    // So Bob can merge the commit and update the local state
                    assert!(bob_central.context.get_conversation(&id).await.is_err());
                    bob_central
                        .context
                        .merge_pending_group_from_external_commit(&id)
                        .await
                        .unwrap();
                    assert!(bob_central.context.get_conversation(&id).await.is_ok());
                    assert_eq!(bob_central.get_conversation_unchecked(&id).await.members().len(), 2);
                    assert!(alice_central.try_talk_to(&id, &bob_central).await.is_ok());

                    // Pending group removed from keystore
                    let error = alice_central
                        .context
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
                    bob_central.context.drop_and_restore(&group_id).await;
                    assert!(bob_central.try_talk_to(&id, &alice_central).await.is_ok());
                })
            },
        )
        .await
    }

    #[apply(all_cred_cipher)]
    #[wasm_bindgen_test]
    async fn join_by_external_commit_should_be_retriable(case: TestCase) {
        run_test_with_client_ids(case.clone(), ["alice", "bob"], move |[alice_central, bob_central]| {
            Box::pin(async move {
                let id = conversation_id();
                alice_central
                    .context
                    .new_conversation(&id, case.credential_type, case.cfg.clone())
                    .await
                    .unwrap();

                // export Alice group info
                let group_info = alice_central.get_group_info(&id).await;

                // Bob tries to join Alice's group
                bob_central
                    .context
                    .join_by_external_commit(group_info.clone(), case.custom_cfg(), case.credential_type)
                    .await
                    .unwrap();
                // BUT for some reason the Delivery Service will reject this external commit
                // e.g. another commit arrived meanwhile and the [GroupInfo] is no longer valid

                // Retrying
                let MlsConversationInitBundle {
                    conversation_id,
                    commit: external_commit,
                    ..
                } = bob_central
                    .context
                    .join_by_external_commit(group_info, case.custom_cfg(), case.credential_type)
                    .await
                    .unwrap();
                assert_eq!(conversation_id.as_slice(), &id);

                // Alice decrypts the external commit and adds Bob
                assert_eq!(alice_central.get_conversation_unchecked(&id).await.members().len(), 1);
                alice_central
                    .context
                    .decrypt_message(&id, &external_commit.to_bytes().unwrap())
                    .await
                    .unwrap();
                assert_eq!(alice_central.get_conversation_unchecked(&id).await.members().len(), 2);

                // And Bob can merge its external commit
                bob_central
                    .context
                    .merge_pending_group_from_external_commit(&id)
                    .await
                    .unwrap();
                assert!(bob_central.context.get_conversation(&id).await.is_ok());
                assert_eq!(bob_central.get_conversation_unchecked(&id).await.members().len(), 2);
                assert!(alice_central.try_talk_to(&id, &bob_central).await.is_ok());
            })
        })
        .await
    }

    #[apply(all_cred_cipher)]
    #[wasm_bindgen_test]
    async fn should_fail_when_bad_epoch(case: TestCase) {
        run_test_with_client_ids(case.clone(), ["alice", "bob"], move |[alice_central, bob_central]| {
            Box::pin(async move {
                let id = conversation_id();
                alice_central
                    .context
                    .new_conversation(&id, case.credential_type, case.cfg.clone())
                    .await
                    .unwrap();

                let group_info = alice_central.get_group_info(&id).await;
                // try to make an external join into Alice's group
                let MlsConversationInitBundle {
                    commit: external_commit,
                    ..
                } = bob_central
                    .context
                    .join_by_external_commit(group_info, case.custom_cfg(), case.credential_type)
                    .await
                    .unwrap();

                // Alice creates a new commit before receiving the external join
                alice_central.context.update_keying_material(&id).await.unwrap();
                alice_central.context.commit_accepted(&id).await.unwrap();

                // receiving the external join with outdated epoch should fail because of
                // the wrong epoch
                let result = alice_central
                    .context
                    .decrypt_message(&id, &external_commit.to_bytes().unwrap())
                    .await;
                assert!(matches!(result.unwrap_err(), crate::CryptoError::StaleCommit));
            })
        })
        .await
    }

    #[apply(all_cred_cipher)]
    #[wasm_bindgen_test]
    async fn existing_clients_can_join(case: TestCase) {
        run_test_with_client_ids(case.clone(), ["alice", "bob"], move |[alice_central, bob_central]| {
            Box::pin(async move {
                let id = conversation_id();
                alice_central
                    .context
                    .new_conversation(&id, case.credential_type, case.cfg.clone())
                    .await
                    .unwrap();
                alice_central.invite_all(&case, &id, [&bob_central]).await.unwrap();
                let group_info = alice_central.get_group_info(&id).await;
                // Alice can rejoin by external commit
                alice_central
                    .context
                    .join_by_external_commit(group_info.clone(), case.custom_cfg(), case.credential_type)
                    .await
                    .unwrap();
                alice_central
                    .context
                    .merge_pending_group_from_external_commit(&id)
                    .await
                    .unwrap();
            })
        })
        .await
    }

    #[apply(all_cred_cipher)]
    #[wasm_bindgen_test]
    async fn should_fail_when_no_pending_external_commit(case: TestCase) {
        run_test_with_central(case.clone(), move |[central]| {
            Box::pin(async move {
                let id = conversation_id();
                // try to merge an inexisting pending group
                let merge_unknown = central.context.merge_pending_group_from_external_commit(&id).await;

                assert!(matches!(
                    merge_unknown.unwrap_err(),
                    crate::CryptoError::KeyStoreError(CryptoKeystoreError::MissingKeyInStore(
                        MissingKeyErrorKind::MlsPendingGroup
                    ))
                ));
            })
        })
        .await
    }

    #[apply(all_cred_cipher)]
    #[wasm_bindgen_test]
    async fn should_return_valid_group_info(case: TestCase) {
        run_test_with_client_ids(
            case.clone(),
            ["alice", "bob", "charlie"],
            move |[alice_central, bob_central, charlie_central]| {
                Box::pin(async move {
                    let id = conversation_id();
                    alice_central
                        .context
                        .new_conversation(&id, case.credential_type, case.cfg.clone())
                        .await
                        .unwrap();

                    // export Alice group info
                    let group_info = alice_central.get_group_info(&id).await;

                    // Bob tries to join Alice's group
                    let MlsConversationInitBundle {
                        commit: bob_external_commit,
                        group_info,
                        ..
                    } = bob_central
                        .context
                        .join_by_external_commit(group_info, case.custom_cfg(), case.credential_type)
                        .await
                        .unwrap();

                    // Alice decrypts the commit, Bob's in !
                    alice_central
                        .context
                        .decrypt_message(&id, &bob_external_commit.to_bytes().unwrap())
                        .await
                        .unwrap();
                    assert_eq!(alice_central.get_conversation_unchecked(&id).await.members().len(), 2);

                    // Bob merges the commit, he's also in !
                    bob_central
                        .context
                        .merge_pending_group_from_external_commit(&id)
                        .await
                        .unwrap();
                    assert!(bob_central.context.get_conversation(&id).await.is_ok());
                    assert_eq!(bob_central.get_conversation_unchecked(&id).await.members().len(), 2);
                    assert!(alice_central.try_talk_to(&id, &bob_central).await.is_ok());

                    // Now charlie wants to join with the [GroupInfo] from Bob's external commit
                    let bob_gi = group_info.get_group_info();
                    let MlsConversationInitBundle {
                        commit: charlie_external_commit,
                        ..
                    } = charlie_central
                        .context
                        .join_by_external_commit(bob_gi, case.custom_cfg(), case.credential_type)
                        .await
                        .unwrap();

                    // Both Alice & Bob decrypt the commit
                    alice_central
                        .context
                        .decrypt_message(&id, charlie_external_commit.to_bytes().unwrap())
                        .await
                        .unwrap();
                    bob_central
                        .context
                        .decrypt_message(&id, charlie_external_commit.to_bytes().unwrap())
                        .await
                        .unwrap();
                    assert_eq!(alice_central.get_conversation_unchecked(&id).await.members().len(), 3);
                    assert_eq!(bob_central.get_conversation_unchecked(&id).await.members().len(), 3);

                    // Charlie merges the commit, he's also in !
                    charlie_central
                        .context
                        .merge_pending_group_from_external_commit(&id)
                        .await
                        .unwrap();
                    assert!(charlie_central.context.get_conversation(&id).await.is_ok());
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
    async fn clear_pending_group_should_succeed(case: TestCase) {
        run_test_with_client_ids(case.clone(), ["alice", "bob"], move |[alice_central, bob_central]| {
            Box::pin(async move {
                let id = conversation_id();
                alice_central
                    .context
                    .new_conversation(&id, case.credential_type, case.cfg.clone())
                    .await
                    .unwrap();

                let initial_count = alice_central.context.count_entities().await;

                // export Alice group info
                let group_info = alice_central.get_group_info(&id).await;

                // Bob tries to join Alice's group
                bob_central
                    .context
                    .join_by_external_commit(group_info, case.custom_cfg(), case.credential_type)
                    .await
                    .unwrap();

                // But for some reason, Bob wants to abort joining the group
                bob_central
                    .context
                    .clear_pending_group_from_external_commit(&id)
                    .await
                    .unwrap();

                let final_count = alice_central.context.count_entities().await;
                assert_eq!(initial_count, final_count);

                // Hence trying to merge the pending should fail
                let result = bob_central.context.merge_pending_group_from_external_commit(&id).await;
                assert!(matches!(
                    result.unwrap_err(),
                    CryptoError::KeyStoreError(CryptoKeystoreError::MissingKeyInStore(
                        MissingKeyErrorKind::MlsPendingGroup
                    ))
                ))
            })
        })
        .await
    }

    #[apply(all_cred_cipher)]
    #[wasm_bindgen_test]
    async fn new_with_inflight_join_should_fail_when_already_exists(case: TestCase) {
        run_test_with_client_ids(case.clone(), ["alice", "bob"], move |[alice_central, bob_central]| {
            Box::pin(async move {
                let id = conversation_id();
                alice_central
                    .context
                    .new_conversation(&id, case.credential_type, case.cfg.clone())
                    .await
                    .unwrap();
                let gi = alice_central.get_group_info(&id).await;

                // Bob to join a conversation but while the server processes its request he
                // creates a conversation with the id of the conversation he's trying to join
                bob_central
                    .context
                    .join_by_external_commit(gi, case.custom_cfg(), case.credential_type)
                    .await
                    .unwrap();
                // erroneous call
                let conflict_join = bob_central
                    .context
                    .new_conversation(&id, case.credential_type, case.cfg.clone())
                    .await;
                assert!(matches!(conflict_join.unwrap_err(), CryptoError::ConversationAlreadyExists(i) if i == id));
            })
        })
        .await
    }

    #[apply(all_cred_cipher)]
    #[wasm_bindgen_test]
    async fn new_with_inflight_welcome_should_fail_when_already_exists(case: TestCase) {
        run_test_with_client_ids(case.clone(), ["alice", "bob"], move |[alice_central, bob_central]| {
            Box::pin(async move {
                let id = conversation_id();
                alice_central
                    .context
                    .new_conversation(&id, case.credential_type, case.cfg.clone())
                    .await
                    .unwrap();
                let gi = alice_central.get_group_info(&id).await;

                // While Bob tries to join a conversation via external commit he's also invited
                // to a conversation with the same id through a Welcome message
                bob_central
                    .context
                    .join_by_external_commit(gi, case.custom_cfg(), case.credential_type)
                    .await
                    .unwrap();

                let bob = bob_central.rand_key_package(&case).await;
                let welcome = alice_central
                    .context
                    .add_members_to_conversation(&id, vec![bob])
                    .await
                    .unwrap()
                    .welcome;

                // erroneous call
                let conflict_welcome = bob_central
                    .context
                    .process_welcome_message(welcome.into(), case.custom_cfg())
                    .await;

                assert!(matches!(conflict_welcome.unwrap_err(), CryptoError::ConversationAlreadyExists(i) if i == id));
            })
        })
        .await
    }

    #[apply(all_cred_cipher)]
    #[wasm_bindgen_test]
    async fn should_fail_when_invalid_group_info(case: TestCase) {
        run_test_with_client_ids(
            case.clone(),
            ["alice", "bob", "guest"],
            move |[alice_central, bob_central, guest_central]| {
                Box::pin(async move {
                    let expiration_time = 14;
                    let start = web_time::Instant::now();
                    let id = conversation_id();
                    alice_central
                        .context
                        .new_conversation(&id, case.credential_type, case.cfg.clone())
                        .await
                        .unwrap();

                    let invalid_kp = bob_central.new_keypackage(&case, Lifetime::new(expiration_time)).await;
                    alice_central
                        .context
                        .add_members_to_conversation(&id, vec![invalid_kp.into()])
                        .await
                        .unwrap();
                    alice_central.context.commit_accepted(&id).await.unwrap();

                    let elapsed = start.elapsed();
                    // Give time to the certificate to expire
                    let expiration_time = core::time::Duration::from_secs(expiration_time);
                    if expiration_time > elapsed {
                        async_std::task::sleep(expiration_time - elapsed + core::time::Duration::from_secs(1)).await;
                    }

                    let group_info = alice_central.get_group_info(&id).await;

                    let join_ext_commit = guest_central
                        .context
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
    async fn group_should_have_right_config(case: TestCase) {
        run_test_with_client_ids(case.clone(), ["alice", "bob"], move |[alice_central, bob_central]| {
            Box::pin(async move {
                let id = conversation_id();
                alice_central
                    .context
                    .new_conversation(&id, case.credential_type, case.cfg.clone())
                    .await
                    .unwrap();

                let gi = alice_central.get_group_info(&id).await;
                bob_central
                    .context
                    .join_by_external_commit(gi, case.custom_cfg(), case.credential_type)
                    .await
                    .unwrap();
                bob_central
                    .context
                    .merge_pending_group_from_external_commit(&id)
                    .await
                    .unwrap();
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
