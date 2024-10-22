use log::{trace, warn};
use openmls::{
    group::QueuedProposal,
    prelude::{GroupEpoch, GroupId, JoinProposal, LeafNodeIndex, MlsMessageOut, Proposal, Sender},
};
use std::collections::HashSet;

use crate::{
    group_store::GroupStoreValue,
    mls::{credential::typ::MlsCredentialType, ClientId, ConversationId, MlsCentral},
    prelude::{CoreCryptoCallbacks, CryptoError, CryptoResult, MlsCiphersuite, MlsConversation, MlsError},
};

impl MlsConversation {
    /// Validates the proposal. If it is external and an `Add` proposal it will call the callback
    /// interface to validate the proposal, otherwise it will succeed.
    pub(crate) async fn validate_external_proposal(
        &self,
        proposal: &QueuedProposal,
        parent_conversation: Option<&GroupStoreValue<MlsConversation>>,
        callbacks: Option<&dyn CoreCryptoCallbacks>,
    ) -> CryptoResult<()> {
        let is_external_proposal = matches!(proposal.sender(), Sender::External(_) | Sender::NewMemberProposal);
        if is_external_proposal {
            if let Proposal::Add(add_proposal) = proposal.proposal() {
                let callbacks = callbacks.ok_or(CryptoError::CallbacksNotSet)?;
                let existing_clients = self.members_in_next_epoch();
                let self_identity = add_proposal.key_package().leaf_node().credential().identity();
                let parent_clients = if let Some(parent_conv) = parent_conversation {
                    Some(
                        parent_conv
                            .read()
                            .await
                            .group
                            .members()
                            .map(|kp| kp.credential.identity().to_vec().into())
                            .collect(),
                    )
                } else {
                    None
                };
                let is_self_user_in_group = callbacks
                    .client_is_existing_group_user(
                        self.id.clone(),
                        self_identity.into(),
                        existing_clients,
                        parent_clients,
                    )
                    .await;
                if !is_self_user_in_group {
                    return Err(CryptoError::UnauthorizedExternalAddProposal);
                }
            }
        } else {
            warn!("Not external proposal.");
        }
        Ok(())
    }

    /// Get actual group members and subtract pending remove proposals
    pub fn members_in_next_epoch(&self) -> Vec<ClientId> {
        let pending_removals = self.pending_removals();
        let existing_clients = self
            .group
            .members()
            .filter_map(|kp| {
                if !pending_removals.contains(&kp.index) {
                    Some(kp.credential.identity().into())
                } else {
                    trace!(client_index:% = kp.index; "Client is pending removal");
                    None
                }
            })
            .collect::<HashSet<_>>();
        existing_clients.into_iter().collect()
    }

    /// Gather pending remove proposals
    fn pending_removals(&self) -> Vec<LeafNodeIndex> {
        self.group
            .pending_proposals()
            .filter_map(|proposal| match proposal.proposal() {
                Proposal::Remove(ref remove) => Some(remove.removed()),
                _ => None,
            })
            .collect::<Vec<_>>()
    }
}

impl MlsCentral {
    /// Crafts a new external Add proposal. Enables a client outside a group to request addition to this group.
    /// For Wire only, the client must belong to an user already in the group
    ///
    /// # Arguments
    /// * `conversation_id` - the group/conversation id
    /// * `epoch` - the current epoch of the group. See [openmls::group::GroupEpoch]
    /// * `ciphersuite` - of the new [openmls::prelude::KeyPackage] to create
    /// * `credential_type` - of the new [openmls::prelude::KeyPackage] to create
    ///
    /// # Return type
    /// Returns a message with the proposal to be add a new client
    ///
    /// # Errors
    /// Errors resulting from the creation of the proposal within OpenMls.
    /// Fails when `credential_type` is [MlsCredentialType::X509] and no Credential has been created
    /// for it beforehand with [MlsCentral::e2ei_mls_init_only] or variants.
    #[cfg_attr(test, crate::dispotent)]
    pub async fn new_external_add_proposal(
        &mut self,
        conversation_id: ConversationId,
        epoch: GroupEpoch,
        ciphersuite: MlsCiphersuite,
        credential_type: MlsCredentialType,
    ) -> CryptoResult<MlsMessageOut> {
        let group_id = GroupId::from_slice(&conversation_id[..]);

        let cb = self
            .mls_client()?
            .find_most_recent_credential_bundle(ciphersuite.signature_algorithm(), credential_type);
        let cb = match (cb, credential_type) {
            (Some(cb), _) => cb,
            (None, MlsCredentialType::Basic) => {
                // If a Basic CredentialBundle does not exist, just create one instead of failing
                self.mls_client
                    .as_mut()
                    .ok_or(CryptoError::MlsNotInitialized)?
                    .init_basic_credential_bundle_if_missing(&self.mls_backend, ciphersuite.signature_algorithm())
                    .await?;

                self.mls_client()?
                    .find_most_recent_credential_bundle(ciphersuite.signature_algorithm(), credential_type)
                    .ok_or(CryptoError::CredentialNotFound(credential_type))?
            }
            (None, MlsCredentialType::X509) => return Err(CryptoError::E2eiEnrollmentNotDone),
        };
        let kp = self
            .mls_client()?
            .generate_one_keypackage_from_credential_bundle(&self.mls_backend, ciphersuite, cb)
            .await?;

        Ok(JoinProposal::new(kp, group_id, epoch, &cb.signature_key).map_err(MlsError::from)?)
    }
}

#[cfg(test)]
mod tests {
    use wasm_bindgen_test::*;

    use crate::{prelude::MlsCommitBundle, test_utils::*};

    wasm_bindgen_test_configure!(run_in_browser);

    mod add {
        use super::*;

        #[apply(all_cred_cipher)]
        #[wasm_bindgen_test]
        async fn guest_should_externally_propose_adding_itself_to_owner_group(case: TestCase) {
            run_test_with_client_ids(
                case.clone(),
                ["owner", "guest"],
                move |[mut owner_central, mut guest_central]| {
                    Box::pin(async move {
                        let id = conversation_id();
                        owner_central
                            .mls_central
                            .new_conversation(&id, case.credential_type, case.cfg.clone())
                            .await
                            .unwrap();
                        let epoch = owner_central
                            .mls_central
                            .get_conversation_unchecked(&id)
                            .await
                            .group
                            .epoch();

                        // Craft an external proposal from guest
                        let external_add = guest_central
                            .mls_central
                            .new_external_add_proposal(id.clone(), epoch, case.ciphersuite(), case.credential_type)
                            .await
                            .unwrap();

                        // Owner receives external proposal message from server
                        let decrypted = owner_central
                            .mls_central
                            .decrypt_message(&id, external_add.to_bytes().unwrap())
                            .await
                            .unwrap();
                        // just owner for now
                        assert_eq!(
                            owner_central
                                .mls_central
                                .get_conversation_unchecked(&id)
                                .await
                                .members()
                                .len(),
                            1
                        );

                        // verify Guest's (sender) identity
                        guest_central.mls_central.verify_sender_identity(&case, &decrypted);

                        // simulate commit message reception from server
                        let MlsCommitBundle { welcome, .. } = owner_central
                            .mls_central
                            .commit_pending_proposals(&id)
                            .await
                            .unwrap()
                            .unwrap();
                        owner_central.mls_central.commit_accepted(&id).await.unwrap();
                        // guest joined the group
                        assert_eq!(
                            owner_central
                                .mls_central
                                .get_conversation_unchecked(&id)
                                .await
                                .members()
                                .len(),
                            2
                        );

                        guest_central
                            .mls_central
                            .process_welcome_message(welcome.unwrap().into(), case.custom_cfg())
                            .await
                            .unwrap();
                        assert_eq!(
                            guest_central
                                .mls_central
                                .get_conversation_unchecked(&id)
                                .await
                                .members()
                                .len(),
                            2
                        );
                        // guest can send messages in the group
                        assert!(guest_central
                            .mls_central
                            .try_talk_to(&id, &mut owner_central.mls_central)
                            .await
                            .is_ok());
                    })
                },
            )
            .await
        }
    }

    mod remove {
        use super::*;
        use crate::prelude::{CryptoError, MlsConversationCreationMessage, MlsConversationInitBundle, MlsError};
        use openmls::prelude::{
            ExternalProposal, GroupId, MlsMessageIn, ProcessMessageError, SenderExtensionIndex, ValidationError,
        };

        #[apply(all_cred_cipher)]
        #[wasm_bindgen_test]
        async fn ds_should_remove_guest_from_conversation(case: TestCase) {
            run_test_with_client_ids(case.clone(), ["owner", "guest", "ds"], move |[owner, guest, ds]| {
                let mut owner_central = owner.mls_central;
                let mut guest_central = guest.mls_central;

                Box::pin(async move {
                    let id = conversation_id();

                    let ds_signature_key = ds.mls_central.client_signature_key(&case).as_slice().to_vec();
                    let mut cfg = case.cfg.clone();
                    owner_central
                        .set_raw_external_senders(&mut cfg, vec![ds_signature_key])
                        .unwrap();
                    owner_central
                        .new_conversation(&id, case.credential_type, cfg)
                        .await
                        .unwrap();

                    owner_central
                        .invite_all(&case, &id, [&mut guest_central])
                        .await
                        .unwrap();
                    assert_eq!(owner_central.get_conversation_unchecked(&id).await.members().len(), 2);

                    // now, as e.g. a Delivery Service, let's create an external remove proposal
                    // and kick guest out of the conversation
                    let to_remove = owner_central.index_of(&id, guest_central.get_client_id()).await;
                    let sender_index = SenderExtensionIndex::new(0);

                    let (sc, ct) = (case.signature_scheme(), case.credential_type);
                    let cb = ds
                        .mls_central
                        .mls_client
                        .as_ref()
                        .unwrap()
                        .find_most_recent_credential_bundle(sc, ct)
                        .unwrap();

                    let group_id = GroupId::from_slice(&id[..]);
                    let epoch = owner_central.get_conversation_unchecked(&id).await.group.epoch();
                    let proposal =
                        ExternalProposal::new_remove(to_remove, group_id, epoch, &cb.signature_key, sender_index)
                            .unwrap();

                    owner_central
                        .decrypt_message(&id, proposal.to_bytes().unwrap())
                        .await
                        .unwrap();
                    guest_central
                        .decrypt_message(&id, proposal.to_bytes().unwrap())
                        .await
                        .unwrap();
                    let MlsCommitBundle { commit, .. } =
                        owner_central.commit_pending_proposals(&id).await.unwrap().unwrap();

                    // before merging, commit is not applied
                    assert_eq!(owner_central.get_conversation_unchecked(&id).await.members().len(), 2);
                    owner_central.commit_accepted(&id).await.unwrap();
                    assert_eq!(owner_central.get_conversation_unchecked(&id).await.members().len(), 1);

                    // guest can no longer participate
                    guest_central
                        .decrypt_message(&id, commit.to_bytes().unwrap())
                        .await
                        .unwrap();
                    assert!(guest_central.get_conversation(&id).await.is_err());
                    assert!(guest_central.try_talk_to(&id, &mut owner_central).await.is_err());
                })
            })
            .await
        }

        #[apply(all_cred_cipher)]
        #[wasm_bindgen_test]
        async fn should_fail_when_invalid_external_sender(case: TestCase) {
            run_test_with_client_ids(
                case.clone(),
                ["owner", "guest", "ds", "attacker"],
                move |[owner, guest, ds, attacker]| {
                    let mut owner_central = owner.mls_central;
                    let mut guest_central = guest.mls_central;

                    Box::pin(async move {
                        let id = conversation_id();
                        // Delivery service key is used in the group..
                        let ds_signature_key = ds.mls_central.client_signature_key(&case).as_slice().to_vec();
                        let mut cfg = case.cfg.clone();
                        owner_central
                            .set_raw_external_senders(&mut cfg, vec![ds_signature_key])
                            .unwrap();
                        owner_central
                            .new_conversation(&id, case.credential_type, cfg)
                            .await
                            .unwrap();

                        owner_central
                            .invite_all(&case, &id, [&mut guest_central])
                            .await
                            .unwrap();
                        assert_eq!(owner_central.get_conversation_unchecked(&id).await.members().len(), 2);

                        // now, attacker will try to remove guest from the group, and should fail
                        let to_remove = owner_central.index_of(&id, guest_central.get_client_id()).await;
                        let sender_index = SenderExtensionIndex::new(1);

                        let (sc, ct) = (case.signature_scheme(), case.credential_type);
                        let cb = attacker
                            .mls_central
                            .mls_client
                            .as_ref()
                            .unwrap()
                            .find_most_recent_credential_bundle(sc, ct)
                            .unwrap();
                        let group_id = GroupId::from_slice(&id[..]);
                        let epoch = owner_central.get_conversation_unchecked(&id).await.group.epoch();
                        let proposal =
                            ExternalProposal::new_remove(to_remove, group_id, epoch, &cb.signature_key, sender_index)
                                .unwrap();

                        let owner_decrypt = owner_central.decrypt_message(&id, proposal.to_bytes().unwrap()).await;

                        assert!(matches!(
                            owner_decrypt.unwrap_err(),
                            CryptoError::MlsError(MlsError::MlsMessageError(ProcessMessageError::ValidationError(
                                ValidationError::UnauthorizedExternalSender
                            )))
                        ));

                        let guest_decrypt = guest_central.decrypt_message(&id, proposal.to_bytes().unwrap()).await;
                        assert!(matches!(
                            guest_decrypt.unwrap_err(),
                            CryptoError::MlsError(MlsError::MlsMessageError(ProcessMessageError::ValidationError(
                                ValidationError::UnauthorizedExternalSender
                            )))
                        ));
                    })
                },
            )
            .await
        }

        #[apply(all_cred_cipher)]
        #[wasm_bindgen_test]
        async fn should_fail_when_wrong_signature_key(case: TestCase) {
            run_test_with_client_ids(case.clone(), ["owner", "guest", "ds"], move |[owner, guest, ds]| {
                let mut owner_central = owner.mls_central;
                let mut guest_central = guest.mls_central;

                Box::pin(async move {
                    let id = conversation_id();

                    // Here we're going to add the Delivery Service's (DS) signature key to the
                    // external senders list. However, for the purpose of this test, we will
                    // intentionally _not_ use that key when generating the remove proposal below.
                    let key = ds.mls_central.client_signature_key(&case).as_slice().to_vec();
                    let mut cfg = case.cfg.clone();
                    owner_central
                        .set_raw_external_senders(&mut cfg, vec![key.as_slice().to_vec()])
                        .unwrap();
                    owner_central
                        .new_conversation(&id, case.credential_type, cfg)
                        .await
                        .unwrap();

                    owner_central
                        .invite_all(&case, &id, [&mut guest_central])
                        .await
                        .unwrap();
                    assert_eq!(owner_central.get_conversation_unchecked(&id).await.members().len(), 2);

                    let to_remove = owner_central.index_of(&id, guest_central.get_client_id()).await;
                    let sender_index = SenderExtensionIndex::new(0);

                    let (sc, ct) = (case.signature_scheme(), case.credential_type);
                    // Intentionally use the guest's credential, and therefore the guest's signature
                    // key when generating the proposal so that the signature verification fails.
                    let cb = guest_central
                        .mls_client
                        .as_ref()
                        .unwrap()
                        .find_most_recent_credential_bundle(sc, ct)
                        .unwrap();
                    let group_id = GroupId::from_slice(&id[..]);
                    let epoch = owner_central.get_conversation_unchecked(&id).await.group.epoch();
                    let proposal =
                        ExternalProposal::new_remove(to_remove, group_id, epoch, &cb.signature_key, sender_index)
                            .unwrap();

                    let owner_decrypt = owner_central.decrypt_message(&id, proposal.to_bytes().unwrap()).await;
                    assert!(matches!(
                        owner_decrypt.unwrap_err(),
                        CryptoError::MlsError(MlsError::MlsMessageError(ProcessMessageError::InvalidSignature))
                    ));

                    let guest_decrypt = guest_central.decrypt_message(&id, proposal.to_bytes().unwrap()).await;
                    assert!(matches!(
                        guest_decrypt.unwrap_err(),
                        CryptoError::MlsError(MlsError::MlsMessageError(ProcessMessageError::InvalidSignature))
                    ));
                })
            })
            .await
        }

        #[apply(all_cred_cipher)]
        #[wasm_bindgen_test]
        async fn joiners_from_welcome_can_accept_external_remove_proposals(case: TestCase) {
            run_test_with_client_ids(
                case.clone(),
                ["alice", "bob", "charlie", "ds"],
                move |[alice, bob, charlie, ds]| {
                    let mut alice_central = alice.mls_central;
                    let mut bob_central = bob.mls_central;
                    let mut charlie_central = charlie.mls_central;

                    Box::pin(async move {
                        let id = conversation_id();

                        let ds_signature_key = ds.mls_central.client_signature_key(&case).as_slice().to_vec();
                        let mut cfg = case.cfg.clone();
                        alice_central
                            .set_raw_external_senders(&mut cfg, vec![ds_signature_key])
                            .unwrap();

                        alice_central
                            .new_conversation(&id, case.credential_type, cfg)
                            .await
                            .unwrap();

                        alice_central.invite_all(&case, &id, [&mut bob_central]).await.unwrap();
                        assert_eq!(alice_central.get_conversation_unchecked(&id).await.members().len(), 2);

                        // Charlie joins through a Welcome and should get external_senders from Welcome
                        // message and not from configuration
                        let charlie = charlie_central.rand_key_package(&case).await;
                        let MlsConversationCreationMessage { welcome, commit, .. } = alice_central
                            .add_members_to_conversation(&id, vec![charlie])
                            .await
                            .unwrap();
                        alice_central.commit_accepted(&id).await.unwrap();
                        bob_central
                            .decrypt_message(&id, commit.to_bytes().unwrap())
                            .await
                            .unwrap();
                        // Purposely have a configuration without `external_senders`
                        charlie_central
                            .process_welcome_message(MlsMessageIn::from(welcome), case.custom_cfg())
                            .await
                            .unwrap();
                        assert_eq!(charlie_central.get_conversation_unchecked(&id).await.members().len(), 3);
                        assert!(charlie_central.try_talk_to(&id, &mut alice_central).await.is_ok());
                        assert!(charlie_central.try_talk_to(&id, &mut bob_central).await.is_ok());

                        // now, as e.g. a Delivery Service, let's create an external remove proposal
                        // and kick Bob out of the conversation
                        let to_remove = alice_central.index_of(&id, bob_central.get_client_id()).await;
                        let sender_index = SenderExtensionIndex::new(0);
                        let (sc, ct) = (case.signature_scheme(), case.credential_type);
                        let cb = ds
                            .mls_central
                            .mls_client
                            .as_ref()
                            .unwrap()
                            .find_most_recent_credential_bundle(sc, ct)
                            .unwrap();
                        let group_id = GroupId::from_slice(&id[..]);
                        let epoch = alice_central.get_conversation_unchecked(&id).await.group.epoch();
                        let proposal =
                            ExternalProposal::new_remove(to_remove, group_id, epoch, &cb.signature_key, sender_index)
                                .unwrap();

                        // joiner from Welcome should be able to verify the external remove proposal since
                        // it has fetched back the external_sender from Welcome
                        let charlie_can_verify_ext_proposal =
                            charlie_central.decrypt_message(&id, proposal.to_bytes().unwrap()).await;
                        assert!(charlie_can_verify_ext_proposal.is_ok());

                        alice_central
                            .decrypt_message(&id, proposal.to_bytes().unwrap())
                            .await
                            .unwrap();
                        bob_central
                            .decrypt_message(&id, proposal.to_bytes().unwrap())
                            .await
                            .unwrap();

                        let commit = charlie_central
                            .commit_pending_proposals(&id)
                            .await
                            .unwrap()
                            .unwrap()
                            .commit;
                        charlie_central.commit_accepted(&id).await.unwrap();
                        assert_eq!(charlie_central.get_conversation_unchecked(&id).await.members().len(), 2);

                        alice_central
                            .decrypt_message(&id, commit.to_bytes().unwrap())
                            .await
                            .unwrap();
                        assert_eq!(alice_central.get_conversation_unchecked(&id).await.members().len(), 2);
                        bob_central
                            .decrypt_message(&id, commit.to_bytes().unwrap())
                            .await
                            .unwrap();
                        assert!(alice_central.try_talk_to(&id, &mut charlie_central).await.is_ok());
                        assert!(alice_central.try_talk_to(&id, &mut bob_central).await.is_err());
                    })
                },
            )
            .await
        }

        #[apply(all_cred_cipher)]
        #[wasm_bindgen_test]
        async fn joiners_from_external_commit_can_accept_external_remove_proposals(case: TestCase) {
            run_test_with_client_ids(
                case.clone(),
                ["alice", "bob", "charlie", "ds"],
                move |[alice, bob, charlie, ds]| {
                    let mut alice_central = alice.mls_central;
                    let mut bob_central = bob.mls_central;
                    let mut charlie_central = charlie.mls_central;

                    Box::pin(async move {
                        let id = conversation_id();

                        let ds_signature_key = ds.mls_central.client_signature_key(&case).as_slice().to_vec();
                        let mut cfg = case.cfg.clone();
                        alice_central
                            .set_raw_external_senders(&mut cfg, vec![ds_signature_key])
                            .unwrap();

                        alice_central
                            .new_conversation(&id, case.credential_type, cfg)
                            .await
                            .unwrap();

                        alice_central.invite_all(&case, &id, [&mut bob_central]).await.unwrap();
                        assert_eq!(alice_central.get_conversation_unchecked(&id).await.members().len(), 2);

                        // Charlie joins through an external commit and should get external_senders
                        // from PGS and not from configuration
                        let public_group_state = alice_central.get_group_info(&id).await;
                        let MlsConversationInitBundle { commit, .. } = charlie_central
                            .join_by_external_commit(public_group_state, case.custom_cfg(), case.credential_type)
                            .await
                            .unwrap();

                        // Purposely have a configuration without `external_senders`
                        charlie_central
                            .merge_pending_group_from_external_commit(&id)
                            .await
                            .unwrap();
                        alice_central
                            .decrypt_message(&id, commit.to_bytes().unwrap())
                            .await
                            .unwrap();
                        bob_central
                            .decrypt_message(&id, commit.to_bytes().unwrap())
                            .await
                            .unwrap();

                        assert_eq!(charlie_central.get_conversation_unchecked(&id).await.members().len(), 3);
                        assert!(charlie_central.try_talk_to(&id, &mut alice_central).await.is_ok());
                        assert!(charlie_central.try_talk_to(&id, &mut bob_central).await.is_ok());

                        // now, as e.g. a Delivery Service, let's create an external remove proposal
                        // and kick Bob out of the conversation
                        let to_remove = alice_central.index_of(&id, bob_central.get_client_id()).await;
                        let sender_index = SenderExtensionIndex::new(0);
                        let (sc, ct) = (case.signature_scheme(), case.credential_type);
                        let cb = ds
                            .mls_central
                            .mls_client
                            .as_ref()
                            .unwrap()
                            .find_most_recent_credential_bundle(sc, ct)
                            .unwrap();
                        let group_id = GroupId::from_slice(&id[..]);
                        let epoch = alice_central.get_conversation_unchecked(&id).await.group.epoch();
                        let proposal =
                            ExternalProposal::new_remove(to_remove, group_id, epoch, &cb.signature_key, sender_index)
                                .unwrap();

                        // joiner from external commit should be able to verify the external remove proposal
                        // since it has fetched back the external_sender from external commit
                        let charlie_can_verify_ext_proposal =
                            charlie_central.decrypt_message(&id, proposal.to_bytes().unwrap()).await;
                        assert!(charlie_can_verify_ext_proposal.is_ok());

                        alice_central
                            .decrypt_message(&id, proposal.to_bytes().unwrap())
                            .await
                            .unwrap();
                        bob_central
                            .decrypt_message(&id, proposal.to_bytes().unwrap())
                            .await
                            .unwrap();

                        let commit = charlie_central
                            .commit_pending_proposals(&id)
                            .await
                            .unwrap()
                            .unwrap()
                            .commit;
                        charlie_central.commit_accepted(&id).await.unwrap();
                        assert_eq!(charlie_central.get_conversation_unchecked(&id).await.members().len(), 2);

                        alice_central
                            .decrypt_message(&id, commit.to_bytes().unwrap())
                            .await
                            .unwrap();
                        assert_eq!(alice_central.get_conversation_unchecked(&id).await.members().len(), 2);
                        bob_central
                            .decrypt_message(&id, commit.to_bytes().unwrap())
                            .await
                            .unwrap();
                        assert!(alice_central.try_talk_to(&id, &mut charlie_central).await.is_ok());
                        assert!(alice_central.try_talk_to(&id, &mut bob_central).await.is_err());
                    })
                },
            )
            .await
        }
    }
}
