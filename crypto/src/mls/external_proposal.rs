use std::collections::HashSet;

use openmls::{
    group::QueuedProposal,
    prelude::{ExternalProposal, GroupEpoch, GroupId, KeyPackageRef, MlsMessageOut, OpenMlsCrypto, Proposal, Sender},
};

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
        parent_conversation: Option<GroupStoreValue<MlsConversation>>,
        callbacks: Option<&dyn CoreCryptoCallbacks>,
        backend: &impl OpenMlsCrypto,
    ) -> CryptoResult<()> {
        let is_external_proposal = matches!(proposal.sender(), Sender::External(_) | Sender::NewMember);
        if is_external_proposal {
            if let Proposal::Add(add_proposal) = proposal.proposal() {
                let callbacks = callbacks.ok_or(CryptoError::CallbacksNotSet)?;
                let existing_clients = self.members_in_next_epoch(backend);
                let self_identity = add_proposal.key_package().credential().identity();
                let parent_clients = if let Some(parent_conv) = parent_conversation {
                    Some(
                        parent_conv
                            .read()
                            .await
                            .group
                            .members()
                            .iter()
                            .map(|kp| kp.credential().identity().to_vec().into())
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
        }
        Ok(())
    }

    /// Get actual group members and subtract pending remove proposals
    pub fn members_in_next_epoch(&self, backend: &impl OpenMlsCrypto) -> Vec<ClientId> {
        let pending_removals = self.pending_removals();
        let existing_clients = self
            .group
            .members()
            .into_iter()
            .filter_map(|kp| {
                if !pending_removals.contains(&&kp.hash_ref(backend).ok()?) {
                    Some(kp.credential().identity().into())
                } else {
                    None
                }
            })
            .collect::<HashSet<_>>();
        existing_clients.into_iter().collect()
    }

    /// Gather pending remove proposals
    fn pending_removals(&self) -> Vec<&KeyPackageRef> {
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
    /// * `epoch` - the current epoch of the group. See [openmls::group::GroupEpoch][GroupEpoch]
    /// * `ciphersuite` - of the new [openmls::prelude::KeyPackage] to create
    /// * `credential_type` - of the new [openmls::prelude::KeyPackage] to create
    ///
    /// # Return type
    /// Returns a message with the proposal to be add a new client
    ///
    /// # Errors
    /// Errors resulting from the creation of the proposal within OpenMls.
    /// Fails when [credential_type] is [MlsCredentialType::X509] and no Credential has been created
    /// for it beforehand with [MlsCentral::e2ei_mls_init] or variants.
    pub async fn new_external_add_proposal(
        &self,
        conversation_id: ConversationId,
        epoch: GroupEpoch,
        ciphersuite: MlsCiphersuite,
        credential_type: MlsCredentialType,
    ) -> CryptoResult<MlsMessageOut> {
        let mls_client = self.mls_client.as_ref().ok_or(CryptoError::MlsNotInitialized)?;

        let group_id = GroupId::from_slice(&conversation_id[..]);

        let cb = mls_client.find_credential_bundle(ciphersuite, credential_type)?;

        let kp = mls_client
            .generate_keypackage_from_credential_bundle(&self.mls_backend, cb, ciphersuite)
            .await?;

        let ext_proposal =
            ExternalProposal::new_add(kp, group_id, epoch, cb, &self.mls_backend).map_err(MlsError::from)?;
        Ok(ext_proposal)
    }

    /// Crafts a new external Remove proposal. Enables a client outside a group to request removal
    /// of a client within the group.
    ///
    /// # Arguments
    /// * `conversation_id` - the group/conversation id
    /// * `epoch` - the current epoch of the group. See [openmls::group::GroupEpoch][GroupEpoch]
    /// * `key_package_ref` - the `KeyPackageRef` of the client to be added to the group
    ///
    /// # Return type
    /// Returns a message with the proposal to be remove a client
    ///
    /// # Errors
    /// Errors resulting from the creation of the proposal within OpenMls
    // TODO: we might not need this after all so let's not complicate things
    pub async fn new_external_remove_proposal(
        &self,
        conversation_id: ConversationId,
        epoch: GroupEpoch,
        key_package_ref: KeyPackageRef,
        ciphersuite: MlsCiphersuite,
        credential_type: MlsCredentialType,
    ) -> CryptoResult<MlsMessageOut> {
        let mls_client = self.mls_client.as_ref().ok_or(CryptoError::MlsNotInitialized)?;

        let cb = mls_client.find_credential_bundle(ciphersuite, credential_type)?;
        // TODO: maybe we should delete this CredentialBundle when this External Remove Proposal is merged.

        let sender_index = 0;
        let group_id = GroupId::from_slice(&conversation_id[..]);
        let ext_proposal =
            ExternalProposal::new_remove(key_package_ref, group_id, epoch, cb, sender_index, &self.mls_backend)
                .map_err(MlsError::from)?;
        Ok(ext_proposal)
    }
}

#[cfg(test)]
mod tests {
    use openmls::prelude::{OpenMlsCryptoProvider, SignaturePublicKey, UnverifiedMessageError};
    use wasm_bindgen_test::*;

    use crate::{
        prelude::{
            handshake::MlsCommitBundle, CryptoError, MlsConversationCreationMessage, MlsConversationInitBundle,
            MlsError,
        },
        test_utils::*,
    };
    use tls_codec::Serialize;

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
                            .new_conversation(id.clone(), case.credential_type, case.cfg.clone())
                            .await
                            .unwrap();
                        let epoch = owner_central.get_conversation_unchecked(&id).await.group.epoch();

                        // Craft an external proposal from guest
                        let external_add = guest_central
                            .new_external_add_proposal(id.clone(), epoch, case.ciphersuite(), case.credential_type)
                            .await
                            .unwrap();

                        // Owner receives external proposal message from server
                        let decrypted = owner_central
                            .decrypt_message(&id, external_add.to_bytes().unwrap())
                            .await
                            .unwrap();
                        // just owner for now
                        assert_eq!(owner_central.get_conversation_unchecked(&id).await.members().len(), 1);

                        // verify Guest's (sender) identity
                        guest_central.verify_sender_identity(&case, &decrypted);

                        // simulate commit message reception from server
                        let MlsCommitBundle { welcome, .. } =
                            owner_central.commit_pending_proposals(&id).await.unwrap().unwrap();
                        owner_central.commit_accepted(&id).await.unwrap();
                        // guest joined the group
                        assert_eq!(owner_central.get_conversation_unchecked(&id).await.members().len(), 2);

                        guest_central
                            .process_welcome_message(welcome.unwrap(), case.custom_cfg())
                            .await
                            .unwrap();
                        assert_eq!(guest_central.get_conversation_unchecked(&id).await.members().len(), 2);
                        // guest can send messages in the group
                        assert!(guest_central.try_talk_to(&id, &mut owner_central).await.is_ok());
                    })
                },
            )
            .await
        }
    }

    mod remove {
        use super::*;
        use openmls_traits::types::SignatureScheme;

        #[apply(all_cred_cipher)]
        #[wasm_bindgen_test]
        async fn ds_should_remove_guest_from_conversation(case: TestCase) {
            run_test_with_client_ids(
                case.clone(),
                ["owner", "guest", "ds"],
                move |[mut owner_central, mut guest_central, ds]| {
                    Box::pin(async move {
                        // TODO since wire-server only sends ed25519 removal keys without metadata we cannot currently support other signature schemes
                        if case.ciphersuite().0.signature_algorithm() == SignatureScheme::ED25519 {
                            let id = conversation_id();

                            let remove_key = ds.client_signature_key(&case).as_slice().to_vec();
                            let mut cfg = case.cfg.clone();
                            cfg.set_raw_external_senders(vec![remove_key]);
                            owner_central
                                .new_conversation(id.clone(), case.credential_type, cfg)
                                .await
                                .unwrap();

                            owner_central
                                .invite(&id, &mut guest_central, case.custom_cfg())
                                .await
                                .unwrap();
                            assert_eq!(owner_central.get_conversation_unchecked(&id).await.members().len(), 2);

                            // now, as e.g. a Delivery Service, let's create an external remove proposal
                            // and kick guest out of the conversation
                            let guest_kp = guest_central.key_package_of(&id, guest_central.read_client_id()).await;
                            let guest_kp_ref = guest_kp.hash_ref(guest_central.mls_backend.crypto()).unwrap();
                            let ext_remove_proposal = ds
                                .new_external_remove_proposal(
                                    id.clone(),
                                    owner_central.get_conversation_unchecked(&id).await.group.epoch(),
                                    guest_kp_ref,
                                    case.ciphersuite(),
                                    case.credential_type,
                                )
                                .await
                                .unwrap();

                            owner_central
                                .decrypt_message(&id, ext_remove_proposal.to_bytes().unwrap())
                                .await
                                .unwrap();
                            guest_central
                                .decrypt_message(&id, ext_remove_proposal.to_bytes().unwrap())
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
                        }
                    })
                },
            )
            .await
        }

        #[apply(all_cred_cipher)]
        #[wasm_bindgen_test]
        async fn should_fail_when_invalid_external_sender(case: TestCase) {
            run_test_with_client_ids(
                case.clone(),
                ["owner", "guest", "ds", "attacker"],
                move |[mut owner_central, mut guest_central, ds, attacker]| {
                    Box::pin(async move {
                        let id = conversation_id();
                        // Delivery service key is used in the group..
                        let remove_key = ds.client_signature_key(&case).as_slice().to_vec();
                        let mut cfg = case.cfg.clone();
                        cfg.set_raw_external_senders(vec![remove_key]);
                        owner_central
                            .new_conversation(id.clone(), case.credential_type, cfg)
                            .await
                            .unwrap();

                        owner_central
                            .invite(&id, &mut guest_central, case.custom_cfg())
                            .await
                            .unwrap();
                        assert_eq!(owner_central.get_conversation_unchecked(&id).await.members().len(), 2);

                        // now, attacker will try to remove guest from the group, and should fail
                        let guest_kp = guest_central.key_package_of(&id, guest_central.read_client_id()).await;
                        let guest_kp_ref = guest_kp.hash_ref(guest_central.mls_backend.crypto()).unwrap();
                        let ext_remove_proposal = attacker
                            .new_external_remove_proposal(
                                id.clone(),
                                owner_central.get_conversation_unchecked(&id).await.group.epoch(),
                                guest_kp_ref,
                                case.ciphersuite(),
                                case.credential_type,
                            )
                            .await
                            .unwrap();

                        let owner_decrypt = owner_central
                            .decrypt_message(&id, ext_remove_proposal.to_bytes().unwrap())
                            .await;
                        assert!(matches!(
                            owner_decrypt.unwrap_err(),
                            CryptoError::MlsError(MlsError::MlsUnverifiedMessageError(
                                UnverifiedMessageError::InvalidSignature
                            ))
                        ));

                        let guest_decrypt = guest_central
                            .decrypt_message(&id, ext_remove_proposal.to_bytes().unwrap())
                            .await;
                        assert!(matches!(
                            guest_decrypt.unwrap_err(),
                            CryptoError::MlsError(MlsError::MlsUnverifiedMessageError(
                                UnverifiedMessageError::InvalidSignature
                            ))
                        ));
                    })
                },
            )
            .await
        }

        #[apply(all_cred_cipher)]
        #[wasm_bindgen_test]
        async fn should_fail_when_invalid_remove_key(case: TestCase) {
            run_test_with_client_ids(
                case.clone(),
                ["owner", "guest", "ds"],
                move |[mut owner_central, mut guest_central, ds]| {
                    Box::pin(async move {
                        let id = conversation_id();

                        let remove_key = ds.client_signature_key(&case);
                        let short_remove_key =
                            SignaturePublicKey::new(remove_key.as_slice()[1..].to_vec(), remove_key.signature_scheme())
                                .unwrap();
                        let short_remove_key = short_remove_key.tls_serialize_detached().unwrap();
                        let mut cfg = case.cfg.clone();
                        cfg.set_raw_external_senders(vec![short_remove_key.as_slice().to_vec()]);
                        owner_central
                            .new_conversation(id.clone(), case.credential_type, cfg)
                            .await
                            .unwrap();

                        owner_central
                            .invite(&id, &mut guest_central, case.custom_cfg())
                            .await
                            .unwrap();
                        assert_eq!(owner_central.get_conversation_unchecked(&id).await.members().len(), 2);

                        // now, as e.g. a Delivery Service, let's create an external remove proposal
                        // and kick guest out of the conversation
                        let guest_kp = guest_central.key_package_of(&id, guest_central.read_client_id()).await;
                        let guest_kp_ref = guest_kp.hash_ref(guest_central.mls_backend.crypto()).unwrap();
                        let ext_remove_proposal = ds
                            .new_external_remove_proposal(
                                id.clone(),
                                owner_central.get_conversation_unchecked(&id).await.group.epoch(),
                                guest_kp_ref,
                                case.ciphersuite(),
                                case.credential_type,
                            )
                            .await
                            .unwrap();

                        let owner_decrypt = owner_central
                            .decrypt_message(&id, ext_remove_proposal.to_bytes().unwrap())
                            .await;
                        assert!(matches!(
                            owner_decrypt.unwrap_err(),
                            CryptoError::MlsError(MlsError::MlsUnverifiedMessageError(
                                UnverifiedMessageError::InvalidSignature
                            ))
                        ));

                        let guest_decrypt = guest_central
                            .decrypt_message(&id, ext_remove_proposal.to_bytes().unwrap())
                            .await;
                        assert!(matches!(
                            guest_decrypt.unwrap_err(),
                            CryptoError::MlsError(MlsError::MlsUnverifiedMessageError(
                                UnverifiedMessageError::InvalidSignature
                            ))
                        ));
                    })
                },
            )
            .await
        }

        #[apply(all_cred_cipher)]
        #[wasm_bindgen_test]
        async fn joiners_from_welcome_can_accept_external_remove_proposals(case: TestCase) {
            // TODO since wire-server only sends ed25519 removal keys without metadata we cannot currently support other signature schemes
            if case.ciphersuite().0.signature_algorithm() == SignatureScheme::ED25519 {
                run_test_with_client_ids(
                    case.clone(),
                    ["alice", "bob", "charlie", "ds"],
                    move |[mut alice_central, mut bob_central, mut charlie_central, ds]| {
                        Box::pin(async move {
                            let id = conversation_id();

                            let remove_key = ds.client_signature_key(&case).as_slice().to_vec();
                            let mut cfg = case.cfg.clone();
                            cfg.set_raw_external_senders(vec![remove_key]);
                            alice_central
                                .new_conversation(id.clone(), case.credential_type, cfg)
                                .await
                                .unwrap();

                            alice_central
                                .invite(&id, &mut bob_central, case.custom_cfg())
                                .await
                                .unwrap();
                            assert_eq!(alice_central.get_conversation_unchecked(&id).await.members().len(), 2);

                            // Charlie joins through a Welcome and should get external_senders from Welcome
                            // message and not from configuration
                            let charlie = charlie_central.rand_member().await;
                            let MlsConversationCreationMessage { welcome, commit, .. } = alice_central
                                .add_members_to_conversation(&id, &mut [charlie])
                                .await
                                .unwrap();
                            alice_central.commit_accepted(&id).await.unwrap();
                            bob_central
                                .decrypt_message(&id, commit.to_bytes().unwrap())
                                .await
                                .unwrap();
                            // Purposely have a configuration without `external_senders`
                            charlie_central
                                .process_welcome_message(welcome, case.custom_cfg())
                                .await
                                .unwrap();
                            assert_eq!(charlie_central.get_conversation_unchecked(&id).await.members().len(), 3);
                            assert!(charlie_central.try_talk_to(&id, &mut alice_central).await.is_ok());
                            assert!(charlie_central.try_talk_to(&id, &mut bob_central).await.is_ok());

                            // now, as e.g. a Delivery Service, let's create an external remove proposal
                            // and kick Bob out of the conversation
                            let bob_kp = bob_central.key_package_of(&id, bob_central.read_client_id()).await;
                            let bob_kp_ref = bob_kp.hash_ref(bob_central.mls_backend.crypto()).unwrap();
                            let ext_remove_proposal = ds
                                .new_external_remove_proposal(
                                    id.clone(),
                                    alice_central.get_conversation_unchecked(&id).await.group.epoch(),
                                    bob_kp_ref,
                                    case.ciphersuite(),
                                    case.credential_type,
                                )
                                .await
                                .unwrap();

                            // joiner from Welcome should be able to verify the external remove proposal since
                            // it has fetched back the external_sender from Welcome
                            let charlie_can_verify_ext_proposal = charlie_central
                                .decrypt_message(&id, ext_remove_proposal.to_bytes().unwrap())
                                .await;
                            assert!(charlie_can_verify_ext_proposal.is_ok());

                            alice_central
                                .decrypt_message(&id, ext_remove_proposal.to_bytes().unwrap())
                                .await
                                .unwrap();
                            bob_central
                                .decrypt_message(&id, ext_remove_proposal.to_bytes().unwrap())
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

        #[apply(all_cred_cipher)]
        #[wasm_bindgen_test]
        async fn joiners_from_external_commit_can_accept_external_remove_proposals(case: TestCase) {
            // TODO since wire-server only sends ed25519 removal keys without metadata we cannot currently support other signature schemes
            if case.ciphersuite().0.signature_algorithm() == SignatureScheme::ED25519 {
                run_test_with_client_ids(
                    case.clone(),
                    ["alice", "bob", "charlie", "ds"],
                    move |[mut alice_central, mut bob_central, mut charlie_central, ds]| {
                        Box::pin(async move {
                            let id = conversation_id();

                            let remove_key = ds.client_signature_key(&case).as_slice().to_vec();
                            let mut cfg = case.cfg.clone();
                            cfg.set_raw_external_senders(vec![remove_key]);
                            alice_central
                                .new_conversation(id.clone(), case.credential_type, cfg)
                                .await
                                .unwrap();

                            alice_central
                                .invite(&id, &mut bob_central, case.custom_cfg())
                                .await
                                .unwrap();
                            assert_eq!(alice_central.get_conversation_unchecked(&id).await.members().len(), 2);

                            // Charlie joins through an external commit and should get external_senders
                            // from PGS and not from configuration
                            let public_group_state = alice_central.verifiable_public_group_state(&id).await;
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
                            let bob_kp = bob_central.key_package_of(&id, bob_central.read_client_id()).await;
                            let bob_kp_ref = bob_kp.hash_ref(bob_central.mls_backend.crypto()).unwrap();
                            let ext_remove_proposal = ds
                                .new_external_remove_proposal(
                                    id.clone(),
                                    alice_central.get_conversation_unchecked(&id).await.group.epoch(),
                                    bob_kp_ref,
                                    case.ciphersuite(),
                                    case.credential_type,
                                )
                                .await
                                .unwrap();

                            // joiner from external commit should be able to verify the external remove proposal
                            // since it has fetched back the external_sender from external commit
                            let charlie_can_verify_ext_proposal = charlie_central
                                .decrypt_message(&id, ext_remove_proposal.to_bytes().unwrap())
                                .await;
                            assert!(charlie_can_verify_ext_proposal.is_ok());

                            alice_central
                                .decrypt_message(&id, ext_remove_proposal.to_bytes().unwrap())
                                .await
                                .unwrap();
                            bob_central
                                .decrypt_message(&id, ext_remove_proposal.to_bytes().unwrap())
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
}
