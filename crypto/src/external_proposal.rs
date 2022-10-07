use std::collections::HashSet;

use openmls::{
    group::QueuedProposal,
    prelude::{ExternalProposal, GroupEpoch, GroupId, KeyPackageRef, MlsMessageOut, OpenMlsCrypto, Proposal, Sender},
};

use crate::{
    prelude::MlsConversation, ConversationId, CoreCryptoCallbacks, CryptoError, CryptoResult, MlsCentral, MlsError,
};

impl MlsConversation {
    /// Validates the proposal. If it is external and an `Add` proposal it will call the callback
    /// interface to validate the proposal, otherwise it will succeed.
    pub(crate) fn validate_external_proposal(
        &self,
        proposal: &QueuedProposal,
        callbacks: Option<&dyn CoreCryptoCallbacks>,
        backend: &impl OpenMlsCrypto,
    ) -> CryptoResult<()> {
        let is_external_proposal = matches!(proposal.sender(), Sender::External(_) | Sender::NewMember);
        if is_external_proposal {
            if let Proposal::Add(add_proposal) = proposal.proposal() {
                let callbacks = callbacks.ok_or(CryptoError::CallbacksNotSet)?;
                let other_clients = self.members_in_next_epoch(backend);
                let self_identity = add_proposal.key_package().credential().identity();
                let is_self_user_in_group =
                    callbacks.client_id_belongs_to_one_of(self_identity.to_vec(), other_clients.into_iter().collect());
                if !is_self_user_in_group {
                    return Err(CryptoError::ExternalAddProposalError);
                }
            }
        }
        Ok(())
    }

    /// Get actual group members and substract pending remove proposals
    fn members_in_next_epoch(&self, backend: &impl OpenMlsCrypto) -> HashSet<Vec<u8>> {
        let pending_removals = self.pending_removals();
        self.group
            .members()
            .into_iter()
            .filter_map(|kp| {
                if !pending_removals.contains(&&kp.hash_ref(backend).ok()?) {
                    Some(kp.credential().identity().to_owned())
                } else {
                    None
                }
            })
            .collect::<HashSet<_>>()
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
    ///
    /// # Return type
    /// Returns a message with the proposal to be add a new client
    ///
    /// # Errors
    /// Errors resulting from the creation of the proposal within OpenMls
    pub async fn new_external_add_proposal(
        &self,
        conversation_id: ConversationId,
        epoch: GroupEpoch,
    ) -> CryptoResult<MlsMessageOut> {
        let group_id = GroupId::from_slice(&conversation_id[..]);
        let (key_package, ..) = self.mls_client.gen_keypackage(&self.mls_backend).await?.into_parts();
        ExternalProposal::new_add(
            key_package,
            group_id,
            epoch,
            self.mls_client.credentials(),
            &self.mls_backend,
        )
        .map_err(MlsError::from)
        .map_err(CryptoError::from)
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
    pub async fn new_external_remove_proposal(
        &self,
        conversation_id: ConversationId,
        epoch: GroupEpoch,
        key_package_ref: KeyPackageRef,
    ) -> CryptoResult<MlsMessageOut> {
        let group_id = GroupId::from_slice(&conversation_id[..]);
        ExternalProposal::new_remove(
            key_package_ref,
            group_id,
            epoch,
            self.mls_client.credentials(),
            // TODO: should inferred from group's extensions
            0,
            &self.mls_backend,
        )
        .map_err(MlsError::from)
        .map_err(CryptoError::from)
    }
}

#[cfg(test)]
mod tests {
    use openmls::prelude::{SignaturePublicKey, UnverifiedMessageError};
    use openmls_traits::OpenMlsCryptoProvider;

    use wasm_bindgen_test::*;

    use crate::{
        credential::CredentialSupplier, prelude::handshake::MlsCommitBundle, test_utils::*, CryptoError,
        MlsConversationConfiguration, MlsError,
    };
    use tls_codec::Serialize;

    wasm_bindgen_test_configure!(run_in_browser);

    mod add {
        use super::*;

        #[apply(all_cipher_cred)]
        #[wasm_bindgen_test]
        async fn guest_should_externally_propose_adding_itself_to_owner_group(
            credential: CredentialSupplier,
            cfg: MlsConversationConfiguration,
        ) {
            run_test_with_client_ids(
                credential,
                ["owner", "guest"],
                move |[mut owner_central, mut guest_central]| {
                    Box::pin(async move {
                        owner_central.callbacks(Box::new(ValidationCallbacks::default()));
                        let id = conversation_id();
                        owner_central
                            .new_conversation(id.clone(), MlsConversationConfiguration::default())
                            .await
                            .unwrap();
                        let epoch = owner_central[&id].group.epoch();

                        // Craft an external proposal from guest
                        let external_add = guest_central
                            .new_external_add_proposal(id.clone(), epoch)
                            .await
                            .unwrap();

                        // Owner receives external proposal message from server
                        owner_central
                            .decrypt_message(&id, external_add.to_bytes().unwrap())
                            .await
                            .unwrap();

                        // just owner for now
                        assert_eq!(owner_central[&id].members().len(), 1);

                        // simulate commit message reception from server
                        let MlsCommitBundle { welcome, .. } =
                            owner_central.commit_pending_proposals(&id).await.unwrap().unwrap();
                        owner_central.commit_accepted(&id).await.unwrap();
                        // guest joined the group
                        assert_eq!(owner_central[&id].members().len(), 2);

                        guest_central
                            .process_welcome_message(welcome.unwrap(), MlsConversationConfiguration::default())
                            .await
                            .unwrap();
                        assert_eq!(guest_central[&id].members().len(), 2);
                        // guest can send messages in the group
                        assert!(guest_central.talk_to(&id, &mut owner_central).await.is_ok());
                    })
                },
            )
            .await
        }
    }

    mod remove {
        use super::*;

        #[apply(all_cipher_cred)]
        #[wasm_bindgen_test]
        async fn ds_should_remove_guest_from_conversation(
            credential: CredentialSupplier,
            cfg: MlsConversationConfiguration,
        ) {
            run_test_with_client_ids(
                credential,
                ["owner", "guest", "ds"],
                move |[mut owner_central, mut guest_central, ds]| {
                    Box::pin(async move {
                        let id = conversation_id();

                        let remove_key = ds
                            .mls_client
                            .credentials()
                            .credential()
                            .signature_key()
                            .as_slice()
                            .to_vec();
                        let cfg = MlsConversationConfiguration {
                            external_senders: vec![remove_key],
                            ..Default::default()
                        };
                        owner_central.new_conversation(id.clone(), cfg).await.unwrap();

                        owner_central.invite(&id, &mut guest_central).await.unwrap();
                        assert_eq!(owner_central[&id].members().len(), 2);

                        // now, as e.g. a Delivery Service, let's create an external remove proposal
                        // and kick guest out of the conversation
                        let guest_kp = guest_central.key_package_of(&id, "guest");
                        let guest_kp_ref = guest_kp.hash_ref(guest_central.mls_backend.crypto()).unwrap();
                        let ext_remove_proposal = ds
                            .new_external_remove_proposal(id.clone(), owner_central[&id].group.epoch(), guest_kp_ref)
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
                        assert_eq!(owner_central[&id].members().len(), 2);
                        owner_central.commit_accepted(&id).await.unwrap();
                        assert_eq!(owner_central[&id].members().len(), 1);

                        // guest can no longer participate
                        guest_central
                            .decrypt_message(&id, commit.to_bytes().unwrap())
                            .await
                            .unwrap();
                        assert!(guest_central.get_conversation(&id).is_err());
                        assert!(guest_central.talk_to(&id, &mut owner_central).await.is_err());
                    })
                },
            )
            .await
        }

        #[apply(all_cipher_cred)]
        #[wasm_bindgen_test]
        async fn should_fail_when_invalid_external_sender(
            credential: CredentialSupplier,
            cfg: MlsConversationConfiguration,
        ) {
            run_test_with_client_ids(
                credential,
                ["owner", "guest", "ds", "attacker"],
                move |[mut owner_central, mut guest_central, ds, attacker]| {
                    Box::pin(async move {
                        owner_central.callbacks(Box::new(ValidationCallbacks::default()));
                        guest_central.callbacks(Box::new(ValidationCallbacks::default()));
                        let id = conversation_id();

                        // Delivery service key is used in the group..
                        let remove_key = ds
                            .mls_client
                            .credentials()
                            .credential()
                            .signature_key()
                            .as_slice()
                            .to_vec();
                        let cfg = MlsConversationConfiguration {
                            external_senders: vec![remove_key],
                            ..Default::default()
                        };
                        owner_central.new_conversation(id.clone(), cfg).await.unwrap();

                        owner_central.invite(&id, &mut guest_central).await.unwrap();
                        assert_eq!(owner_central[&id].members().len(), 2);

                        // now, attacker will try to remove guest from the group, and should fail
                        let guest_kp = guest_central.key_package_of(&id, "guest");
                        let guest_kp_ref = guest_kp.hash_ref(guest_central.mls_backend.crypto()).unwrap();
                        let ext_remove_proposal = attacker
                            .new_external_remove_proposal(id.clone(), owner_central[&id].group.epoch(), guest_kp_ref)
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

        #[apply(all_cipher_cred)]
        #[wasm_bindgen_test]
        async fn should_fail_when_invalid_remove_key(
            credential: CredentialSupplier,
            cfg: MlsConversationConfiguration,
        ) {
            run_test_with_client_ids(
                credential,
                ["owner", "guest", "ds"],
                move |[mut owner_central, mut guest_central, ds]| {
                    Box::pin(async move {
                        owner_central.callbacks(Box::new(ValidationCallbacks::default()));
                        guest_central.callbacks(Box::new(ValidationCallbacks::default()));
                        let id = conversation_id();

                        let remove_key = ds.mls_client.credentials().credential().signature_key();
                        let short_remove_key =
                            SignaturePublicKey::new(remove_key.as_slice()[1..].to_vec(), remove_key.signature_scheme())
                                .unwrap();
                        let short_remove_key = short_remove_key.tls_serialize_detached().unwrap();
                        let cfg = MlsConversationConfiguration {
                            external_senders: vec![short_remove_key.as_slice().to_vec()],
                            ..Default::default()
                        };
                        owner_central.new_conversation(id.clone(), cfg).await.unwrap();

                        owner_central.invite(&id, &mut guest_central).await.unwrap();
                        assert_eq!(owner_central[&id].members().len(), 2);

                        // now, as e.g. a Delivery Service, let's create an external remove proposal
                        // and kick guest out of the conversation
                        let guest_kp = guest_central.key_package_of(&id, "guest");
                        let guest_kp_ref = guest_kp.hash_ref(guest_central.mls_backend.crypto()).unwrap();
                        let ext_remove_proposal = ds
                            .new_external_remove_proposal(id.clone(), owner_central[&id].group.epoch(), guest_kp_ref)
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
    }
}
