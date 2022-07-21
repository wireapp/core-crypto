use std::collections::HashSet;

use crate::{
    prelude::MlsConversation, ConversationId, CoreCryptoCallbacks, CryptoError, CryptoResult, MlsCentral, MlsError,
};
use openmls::{
    group::QueuedProposal,
    prelude::{
        ExternalProposal, GroupEpoch, GroupId, KeyPackage, KeyPackageRef, MlsMessageOut, OpenMlsCrypto, Proposal,
        Sender,
    },
};

pub(crate) trait ExternalProposalExt {
    fn is_external_add_proposal(&self) -> bool;
}
impl ExternalProposalExt for QueuedProposal {
    fn is_external_add_proposal(&self) -> bool {
        matches!(
            (self.proposal(), self.sender()),
            (Proposal::Add(_), Sender::Preconfigured(_) | Sender::NewMember)
        )
    }
}

impl MlsConversation {
    /// Validates the proposal. If it is external and an `Add` proposal it will call the callback
    /// interface to validate the proposal, otherwise it will succeed.
    pub(crate) fn validate_external_proposal(
        &self,
        proposal: &QueuedProposal,
        callbacks: &(impl CoreCryptoCallbacks + ?Sized),
        backend: &impl OpenMlsCrypto,
    ) -> CryptoResult<()> {
        if proposal.is_external_add_proposal() {
            let pending_removes = self
                .group
                .pending_proposals()
                .filter_map(|proposal| match proposal.proposal() {
                    Proposal::Remove(ref remove) => Some(remove.removed()),
                    _ => None,
                })
                .collect::<Vec<_>>();
            let other_clients = self
                .group
                .members()
                .into_iter()
                .filter_map(|kp| {
                    if !pending_removes.contains(&&kp.hash_ref(backend).ok()?) {
                        Some(kp.credential().identity().to_owned())
                    } else {
                        None
                    }
                })
                .collect::<HashSet<_>>();
            let add_proposal = match proposal.proposal() {
                Proposal::Add(ref add) => add,
                _ => return Err(CryptoError::InvalidProposalType),
            };
            if !callbacks.is_user_in_group(
                add_proposal.key_package().credential().identity().to_owned(),
                other_clients.into_iter().collect(),
            ) {
                return Err(CryptoError::ExternalProposalError(
                    "identity validation failure. Only users already in group are allowed.",
                ));
            }
        }
        Ok(())
    }
}

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
    use crate::{
        credential::CredentialSupplier, prelude::handshake::MlsCommitBundle, test_utils::*,
        MlsConversationConfiguration,
    };
    use openmls_traits::OpenMlsCryptoProvider;
    use wasm_bindgen_test::*;

    wasm_bindgen_test_configure!(run_in_browser);

    mod add {

        use super::*;

        #[apply(all_credential_types)]
        #[wasm_bindgen_test]
        async fn guest_should_externally_propose_adding_itself_to_owner_group(credential: CredentialSupplier) {
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
                        let guest_kp = guest_central.get_one_key_package().await;

                        // Craft an external proposal from guest
                        let external_add = guest_central
                            .new_external_add_proposal(id.clone(), epoch, guest_kp)
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
                            owner_central.commit_pending_proposals(&id).await.unwrap();
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

        #[apply(all_credential_types)]
        #[wasm_bindgen_test]
        async fn ds_should_remove_guest_from_conversation(credential: CredentialSupplier) {
            run_test_with_client_ids(
                credential,
                ["owner", "guest", "ds"],
                move |[mut owner_central, mut guest_central, ds]| {
                    Box::pin(async move {
                        owner_central.callbacks(Box::new(ValidationCallbacks::default()));
                        guest_central.callbacks(Box::new(ValidationCallbacks::default()));
                        let id = conversation_id();
                        let cfg = MlsConversationConfiguration {
                            external_senders: vec![ds.mls_client.credentials().credential().to_owned()],
                            ..Default::default()
                        };
                        owner_central.new_conversation(id.clone(), cfg).await.unwrap();

                        owner_central.invite(&id, &mut guest_central).await.unwrap();
                        owner_central.commit_accepted(&id).await.unwrap();
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
                        let MlsCommitBundle { commit, .. } = owner_central.commit_pending_proposals(&id).await.unwrap();
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
    }
}
