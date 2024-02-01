use std::collections::HashSet;

use openmls::prelude::{JoinProposal, LeafNodeIndex};
use openmls::{
    group::QueuedProposal,
    prelude::{GroupEpoch, GroupId, MlsMessageOut, Proposal, Sender},
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
    /// * `epoch` - the current epoch of the group. See [openmls::group::GroupEpoch][GroupEpoch]
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

        let ext_proposal = JoinProposal::new(kp, group_id, epoch, &cb.signature_key).map_err(MlsError::from)?;
        Ok(ext_proposal)
    }
}

#[cfg(test)]
pub mod tests {
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
}
