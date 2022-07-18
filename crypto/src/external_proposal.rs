use openmls::prelude::{ExternalProposal, GroupEpoch, GroupId, KeyPackage, KeyPackageRef, MlsMessageOut};

use crate::{ConversationId, CryptoError, CryptoResult, MlsCentral, MlsError};

impl MlsCentral {
    /// Crafts a new external Add proposal. Enables a client outside a group to request addition to this group.
    /// For Wire only, the client must belong to an user already in the group
    ///
    /// # Arguments
    /// * `conversation_id` - the group/conversation id
    /// * `epoch` - the current epoch of the group. See [openmls::group::GroupEpoch][GroupEpoch]
    /// * `key_package` - the `KeyPackage` of the client to be added to the group
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
        key_package: KeyPackage,
    ) -> CryptoResult<MlsMessageOut> {
        let group_id = GroupId::from_slice(&conversation_id[..]);
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
            &self.mls_backend,
        )
        .map_err(MlsError::from)
        .map_err(CryptoError::from)
    }
}

#[cfg(test)]
mod tests {
    use openmls_traits::OpenMlsCryptoProvider;
    use wasm_bindgen_test::*;

    use crate::{
        credential::CredentialSupplier, member::ConversationMember, test_fixture_utils::*, test_utils::*,
        MlsConversationConfiguration,
    };

    wasm_bindgen_test_configure!(run_in_browser);

    mod add {
        use super::*;

        #[apply(all_credential_types)]
        #[wasm_bindgen_test]
        async fn should_succeed(credential: CredentialSupplier) {
            run_test_with_client_ids(
                credential,
                ["owner@wire.com", "guest@wire.com"],
                move |[mut owner_central, mut guest_central]| {
                    Box::pin(async move {
                        let conversation_id = b"owner-guest".to_vec();
                        owner_central
                            .new_conversation(conversation_id.clone(), MlsConversationConfiguration::default())
                            .await
                            .unwrap();
                        let owner_group = owner_central.mls_groups.get_mut(&conversation_id).unwrap();
                        let epoch = owner_group.group.epoch();

                        let guest_key_packages = guest_central.client_keypackages(1).await.unwrap();
                        let guest_key_package = guest_key_packages.get(0).unwrap().key_package().to_owned();

                        // Craft an external proposal from guest
                        let add_message = guest_central
                            .new_external_add_proposal(owner_group.id.clone(), epoch, guest_key_package)
                            .await
                            .unwrap();

                        // Owner receives external proposal message from server
                        owner_central
                            .decrypt_message(&conversation_id, add_message.to_bytes().unwrap().as_slice())
                            .await
                            .unwrap();

                        let owner_group = owner_central.mls_groups.get_mut(&conversation_id).unwrap();

                        // just owner
                        assert_eq!(owner_group.members().len(), 1);

                        // simulate commit message reception from server
                        let (_, welcome) = owner_group
                            .commit_pending_proposals(&owner_central.mls_backend)
                            .await
                            .unwrap();
                        owner_group.commit_accepted(&owner_central.mls_backend).await.unwrap();

                        let welcome = welcome.unwrap();

                        // owner + guest
                        assert_eq!(owner_group.members().len(), 2);

                        guest_central
                            .process_welcome_message(welcome, MlsConversationConfiguration::default())
                            .await
                            .unwrap();

                        // guest can send messages in the group
                        assert!(guest_central
                            .encrypt_message(&conversation_id, b"hello owner")
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

        #[apply(all_credential_types)]
        #[wasm_bindgen_test]
        async fn should_succeed(credential: CredentialSupplier) {
            run_test_with_client_ids(
                credential,
                ["owner@wire.com", "guest@wire.com", "ds@wire.com"],
                move |[mut owner_central, guest_central, ds]| {
                    Box::pin(async move {
                        let conversation_id = b"owner-guest".to_vec();
                        let cfg = MlsConversationConfiguration {
                            external_senders: vec![ds.mls_client.credentials().credential().to_owned()],
                            ..Default::default()
                        };
                        owner_central
                            .new_conversation(conversation_id.clone(), cfg)
                            .await
                            .unwrap();
                        // adding guest to the conversation
                        let guest_id = guest_central.mls_client.id().to_owned();
                        let guest_kp = guest_central.get_one_key_package().await.unwrap();
                        let guest_kp_ref = guest_kp.hash_ref(guest_central.mls_backend.crypto()).unwrap();
                        let guest = ConversationMember::new(guest_id, guest_kp);
                        let owner_group = owner_central.mls_groups.get_mut(&conversation_id).unwrap();
                        owner_group
                            .add_members(&mut [guest], &owner_central.mls_backend)
                            .await
                            .unwrap();
                        owner_group.commit_accepted(&owner_central.mls_backend).await.unwrap();
                        assert_eq!(owner_group.members().len(), 2);

                        // now, as e.g. a Delivery Service, let's create an external remove proposal
                        // and kick guest out of the conversation
                        let ext_remove_proposal = ds
                            .new_external_remove_proposal(
                                owner_group.id.clone(),
                                owner_group.group.epoch(),
                                guest_kp_ref,
                            )
                            .await
                            .unwrap();

                        owner_group
                            .decrypt_message(
                                ext_remove_proposal.to_bytes().unwrap().as_slice(),
                                &owner_central.mls_backend,
                            )
                            .await
                            .unwrap();
                        owner_group
                            .commit_pending_proposals(&owner_central.mls_backend)
                            .await
                            .unwrap();
                        // before merging, commit is not applied
                        assert_eq!(owner_group.members().len(), 2);
                        owner_group.commit_accepted(&owner_central.mls_backend).await.unwrap();
                        assert_eq!(owner_group.members().len(), 1);
                    })
                },
            )
            .await
        }
    }
}
