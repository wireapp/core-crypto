use openmls::prelude::{GroupEpoch, GroupId, JoinProposal, MlsMessageOut};

use super::Result;
use crate::{
    LeafError, MlsError, RecursiveError,
    mls::{self, credential::typ::MlsCredentialType},
    prelude::{ConversationId, MlsCiphersuite},
    transaction_context::TransactionContext,
};

impl TransactionContext {
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
    /// for it beforehand with [TransactionContext::e2ei_mls_init_only] or variants.
    #[cfg_attr(test, crate::dispotent)]
    pub async fn new_external_add_proposal(
        &self,
        conversation_id: ConversationId,
        epoch: GroupEpoch,
        ciphersuite: MlsCiphersuite,
        credential_type: MlsCredentialType,
    ) -> Result<MlsMessageOut> {
        let group_id = GroupId::from_slice(conversation_id.as_slice());
        let mls_provider = self
            .mls_provider()
            .await
            .map_err(RecursiveError::transaction("getting mls provider"))?;

        let client = self
            .session()
            .await
            .map_err(RecursiveError::transaction("getting mls client"))?;
        let cb = client
            .find_most_recent_credential_bundle(ciphersuite.signature_algorithm(), credential_type)
            .await;
        let cb = match (cb, credential_type) {
            (Ok(cb), _) => cb,
            (Err(mls::session::Error::CredentialNotFound(_)), MlsCredentialType::Basic) => {
                // If a Basic CredentialBundle does not exist, just create one instead of failing
                client
                    .init_basic_credential_bundle_if_missing(&mls_provider, ciphersuite.signature_algorithm())
                    .await
                    .map_err(RecursiveError::mls_client(
                        "initializing basic credential bundle if missing",
                    ))?;

                client
                    .find_most_recent_credential_bundle(ciphersuite.signature_algorithm(), credential_type)
                    .await
                    .map_err(RecursiveError::mls_client(
                        "finding most recent credential bundle (which we just created)",
                    ))?
            }
            (Err(mls::session::Error::CredentialNotFound(_)), MlsCredentialType::X509) => {
                return Err(LeafError::E2eiEnrollmentNotDone.into());
            }
            (Err(e), _) => return Err(RecursiveError::mls_client("finding most recent credential bundle")(e).into()),
        };
        let kp = client
            .generate_one_keypackage_from_credential_bundle(&mls_provider, ciphersuite, &cb)
            .await
            .map_err(RecursiveError::mls_client(
                "generating one keypackage from credential bundle",
            ))?;

        JoinProposal::new(kp, group_id, epoch, &cb.signature_key)
            .map_err(MlsError::wrap("creating join proposal"))
            .map_err(Into::into)
    }
}

#[cfg(test)]
mod tests {
    use wasm_bindgen_test::*;

    use crate::test_utils::*;

    wasm_bindgen_test_configure!(run_in_browser);

    mod add {
        use super::*;

        #[apply(all_cred_cipher)]
        #[wasm_bindgen_test]
        async fn guest_should_externally_propose_adding_itself_to_owner_group(case: TestContext) {
            let [owner_central, guest_central] = case.sessions().await;
            Box::pin(async move {
                let id = conversation_id();
                owner_central
                    .transaction
                    .new_conversation(&id, case.credential_type, case.cfg.clone())
                    .await
                    .unwrap();
                let epoch = owner_central.get_conversation_unchecked(&id).await.group.epoch();

                // Craft an external proposal from guest
                let external_add = guest_central
                    .transaction
                    .new_external_add_proposal(id.clone(), epoch, case.ciphersuite(), case.credential_type)
                    .await
                    .unwrap();

                // Owner receives external proposal message from server
                let decrypted = owner_central
                    .transaction
                    .conversation(&id)
                    .await
                    .unwrap()
                    .decrypt_message(external_add.to_bytes().unwrap())
                    .await
                    .unwrap();
                // just owner for now
                assert_eq!(owner_central.get_conversation_unchecked(&id).await.members().len(), 1);

                // verify Guest's (sender) identity
                guest_central.verify_sender_identity(&case, &decrypted).await;

                // simulate commit message reception from server
                owner_central
                    .transaction
                    .conversation(&id)
                    .await
                    .unwrap()
                    .commit_pending_proposals()
                    .await
                    .unwrap();
                // guest joined the group
                assert_eq!(owner_central.get_conversation_unchecked(&id).await.members().len(), 2);

                let welcome = guest_central.mls_transport().await.latest_welcome_message().await;
                guest_central
                    .transaction
                    .process_welcome_message(welcome.into(), case.custom_cfg())
                    .await
                    .unwrap();
                assert_eq!(guest_central.get_conversation_unchecked(&id).await.members().len(), 2);
                // guest can send messages in the group
                assert!(guest_central.try_talk_to(&id, &owner_central).await.is_ok());
            })
            .await
        }
    }

    mod remove {
        use super::*;
        use crate::{MlsErrorKind, prelude::MlsError};
        use openmls::prelude::{
            ExternalProposal, GroupId, MlsMessageIn, ProcessMessageError, SenderExtensionIndex, ValidationError,
        };

        #[apply(all_cred_cipher)]
        #[wasm_bindgen_test]
        async fn ds_should_remove_guest_from_conversation(case: TestContext) {
            let [owner, guest, ds] = case.sessions().await;
            Box::pin(async move {
                let owner_central = &owner.transaction;
                let guest_central = &guest.transaction;
                let id = conversation_id();

                let ds_signature_key = ds.client_signature_key(&case).await.as_slice().to_vec();
                let mut cfg = case.cfg.clone();
                owner_central
                    .set_raw_external_senders(&mut cfg, vec![ds_signature_key])
                    .await
                    .unwrap();
                owner_central
                    .new_conversation(&id, case.credential_type, cfg)
                    .await
                    .unwrap();

                owner.invite_all(&case, &id, [&guest]).await.unwrap();
                assert_eq!(owner.get_conversation_unchecked(&id).await.members().len(), 2);

                // now, as e.g. a Delivery Service, let's create an external remove proposal
                // and kick guest out of the conversation
                let to_remove = owner.index_of(&id, guest.get_client_id().await).await;
                let sender_index = SenderExtensionIndex::new(0);

                let (sc, ct) = (case.signature_scheme(), case.credential_type);
                let cb = ds.find_most_recent_credential_bundle(sc, ct).await.unwrap();

                let group_id = GroupId::from_slice(&id[..]);
                let epoch = owner.get_conversation_unchecked(&id).await.group.epoch();
                let proposal =
                    ExternalProposal::new_remove(to_remove, group_id, epoch, &cb.signature_key, sender_index).unwrap();

                owner_central
                    .conversation(&id)
                    .await
                    .unwrap()
                    .decrypt_message(proposal.to_bytes().unwrap())
                    .await
                    .unwrap();
                guest_central
                    .conversation(&id)
                    .await
                    .unwrap()
                    .decrypt_message(proposal.to_bytes().unwrap())
                    .await
                    .unwrap();
                owner_central
                    .conversation(&id)
                    .await
                    .unwrap()
                    .commit_pending_proposals()
                    .await
                    .unwrap();
                let commit = owner.mls_transport().await.latest_commit().await;

                assert_eq!(owner.get_conversation_unchecked(&id).await.members().len(), 1);

                // guest can no longer participate
                guest_central
                    .conversation(&id)
                    .await
                    .unwrap()
                    .decrypt_message(commit.to_bytes().unwrap())
                    .await
                    .unwrap();
                assert!(guest_central.conversation(&id).await.is_err());
                assert!(guest.try_talk_to(&id, &owner).await.is_err());
            })
            .await
        }

        #[apply(all_cred_cipher)]
        #[wasm_bindgen_test]
        async fn should_fail_when_invalid_external_sender(case: TestContext) {
            use crate::mls;

            let [owner, guest, ds, attacker] = case.sessions().await;
            Box::pin(async move {
                let id = conversation_id();
                // Delivery service key is used in the group..
                let ds_signature_key = ds.client_signature_key(&case).await.as_slice().to_vec();
                let mut cfg = case.cfg.clone();
                owner
                    .transaction
                    .set_raw_external_senders(&mut cfg, vec![ds_signature_key])
                    .await
                    .unwrap();
                owner
                    .transaction
                    .new_conversation(&id, case.credential_type, cfg)
                    .await
                    .unwrap();

                owner.invite_all(&case, &id, [&guest]).await.unwrap();
                assert_eq!(owner.get_conversation_unchecked(&id).await.members().len(), 2);

                // now, attacker will try to remove guest from the group, and should fail
                let to_remove = owner.index_of(&id, guest.get_client_id().await).await;
                let sender_index = SenderExtensionIndex::new(1);

                let (sc, ct) = (case.signature_scheme(), case.credential_type);
                let cb = attacker.find_most_recent_credential_bundle(sc, ct).await.unwrap();
                let group_id = GroupId::from_slice(&id[..]);
                let epoch = owner.get_conversation_unchecked(&id).await.group.epoch();
                let proposal =
                    ExternalProposal::new_remove(to_remove, group_id, epoch, &cb.signature_key, sender_index).unwrap();

                let owner_decrypt = owner
                    .transaction
                    .conversation(&id)
                    .await
                    .unwrap()
                    .decrypt_message(proposal.to_bytes().unwrap())
                    .await;

                assert!(matches!(
                    owner_decrypt.unwrap_err(),
                    mls::conversation::Error::Mls(MlsError {
                        source: MlsErrorKind::MlsMessageError(ProcessMessageError::ValidationError(
                            ValidationError::UnauthorizedExternalSender
                        )),
                        ..
                    })
                ));

                let guest_decrypt = owner
                    .transaction
                    .conversation(&id)
                    .await
                    .unwrap()
                    .decrypt_message(proposal.to_bytes().unwrap())
                    .await;
                assert!(matches!(
                    guest_decrypt.unwrap_err(),
                    mls::conversation::Error::Mls(MlsError {
                        source: MlsErrorKind::MlsMessageError(ProcessMessageError::ValidationError(
                            ValidationError::UnauthorizedExternalSender
                        )),
                        ..
                    })
                ));
            })
            .await
        }

        #[apply(all_cred_cipher)]
        #[wasm_bindgen_test]
        async fn should_fail_when_wrong_signature_key(case: TestContext) {
            use crate::mls;

            let [owner, guest, ds] = case.sessions().await;
            Box::pin(async move {
                let id = conversation_id();

                // Here we're going to add the Delivery Service's (DS) signature key to the
                // external senders list. However, for the purpose of this test, we will
                // intentionally _not_ use that key when generating the remove proposal below.
                let key = ds.client_signature_key(&case).await.as_slice().to_vec();
                let mut cfg = case.cfg.clone();
                owner
                    .transaction
                    .set_raw_external_senders(&mut cfg, vec![key.as_slice().to_vec()])
                    .await
                    .unwrap();
                owner
                    .transaction
                    .new_conversation(&id, case.credential_type, cfg)
                    .await
                    .unwrap();

                owner.invite_all(&case, &id, [&guest]).await.unwrap();
                assert_eq!(owner.get_conversation_unchecked(&id).await.members().len(), 2);

                let to_remove = owner.index_of(&id, guest.get_client_id().await).await;
                let sender_index = SenderExtensionIndex::new(0);

                let (sc, ct) = (case.signature_scheme(), case.credential_type);
                // Intentionally use the guest's credential, and therefore the guest's signature
                // key when generating the proposal so that the signature verification fails.
                let cb = guest.find_most_recent_credential_bundle(sc, ct).await.unwrap();
                let group_id = GroupId::from_slice(&id[..]);
                let epoch = owner.get_conversation_unchecked(&id).await.group.epoch();
                let proposal =
                    ExternalProposal::new_remove(to_remove, group_id, epoch, &cb.signature_key, sender_index).unwrap();

                let owner_decrypt = owner
                    .transaction
                    .conversation(&id)
                    .await
                    .unwrap()
                    .decrypt_message(proposal.to_bytes().unwrap())
                    .await;
                assert!(matches!(
                    owner_decrypt.unwrap_err(),
                    mls::conversation::Error::Mls(MlsError {
                        source: MlsErrorKind::MlsMessageError(ProcessMessageError::InvalidSignature),
                        ..
                    })
                ));

                let guest_decrypt = owner
                    .transaction
                    .conversation(&id)
                    .await
                    .unwrap()
                    .decrypt_message(proposal.to_bytes().unwrap())
                    .await;
                assert!(matches!(
                    guest_decrypt.unwrap_err(),
                    mls::conversation::Error::Mls(MlsError {
                        source: MlsErrorKind::MlsMessageError(ProcessMessageError::InvalidSignature),
                        ..
                    })
                ));
            })
            .await
        }

        #[apply(all_cred_cipher)]
        #[wasm_bindgen_test]
        async fn joiners_from_welcome_can_accept_external_remove_proposals(case: TestContext) {
            let [alice, bob, charlie, ds] = case.sessions().await;
            Box::pin(async move {
                let alice_central = &alice.transaction;
                let bob_central = &bob.transaction;
                let charlie_central = &charlie.transaction;
                let id = conversation_id();

                let ds_signature_key = ds.client_signature_key(&case).await.as_slice().to_vec();
                let mut cfg = case.cfg.clone();
                alice_central
                    .set_raw_external_senders(&mut cfg, vec![ds_signature_key])
                    .await
                    .unwrap();

                alice_central
                    .new_conversation(&id, case.credential_type, cfg)
                    .await
                    .unwrap();

                alice.invite_all(&case, &id, [&bob]).await.unwrap();
                assert_eq!(alice.get_conversation_unchecked(&id).await.members().len(), 2);

                // Charlie joins through a Welcome and should get external_senders from Welcome
                // message and not from configuration
                let charlie_kp = charlie.rand_key_package(&case).await;
                alice_central
                    .conversation(&id)
                    .await
                    .unwrap()
                    .add_members(vec![charlie_kp])
                    .await
                    .unwrap();
                let welcome = alice.mls_transport().await.latest_welcome_message().await;
                let commit = alice.mls_transport().await.latest_commit().await;
                bob_central
                    .conversation(&id)
                    .await
                    .unwrap()
                    .decrypt_message(commit.to_bytes().unwrap())
                    .await
                    .unwrap();
                // Purposely have a configuration without `external_senders`
                charlie_central
                    .process_welcome_message(MlsMessageIn::from(welcome), case.custom_cfg())
                    .await
                    .unwrap();
                assert_eq!(charlie.get_conversation_unchecked(&id).await.members().len(), 3);
                assert!(charlie.try_talk_to(&id, &alice).await.is_ok());
                assert!(charlie.try_talk_to(&id, &bob).await.is_ok());

                // now, as e.g. a Delivery Service, let's create an external remove proposal
                // and kick Bob out of the conversation
                let to_remove = alice.index_of(&id, bob.get_client_id().await).await;
                let sender_index = SenderExtensionIndex::new(0);
                let (sc, ct) = (case.signature_scheme(), case.credential_type);
                let cb = ds.find_most_recent_credential_bundle(sc, ct).await.unwrap();
                let group_id = GroupId::from_slice(&id[..]);
                let epoch = alice.get_conversation_unchecked(&id).await.group.epoch();
                let proposal =
                    ExternalProposal::new_remove(to_remove, group_id, epoch, &cb.signature_key, sender_index).unwrap();

                // joiner from Welcome should be able to verify the external remove proposal since
                // it has fetched back the external_sender from Welcome
                let charlie_can_verify_ext_proposal = charlie_central
                    .conversation(&id)
                    .await
                    .unwrap()
                    .decrypt_message(proposal.to_bytes().unwrap())
                    .await;
                assert!(charlie_can_verify_ext_proposal.is_ok());

                alice_central
                    .conversation(&id)
                    .await
                    .unwrap()
                    .decrypt_message(proposal.to_bytes().unwrap())
                    .await
                    .unwrap();
                bob_central
                    .conversation(&id)
                    .await
                    .unwrap()
                    .decrypt_message(proposal.to_bytes().unwrap())
                    .await
                    .unwrap();

                charlie_central
                    .conversation(&id)
                    .await
                    .unwrap()
                    .commit_pending_proposals()
                    .await
                    .unwrap();
                let commit = charlie.mls_transport().await.latest_commit().await;
                assert_eq!(charlie.get_conversation_unchecked(&id).await.members().len(), 2);

                alice_central
                    .conversation(&id)
                    .await
                    .unwrap()
                    .decrypt_message(commit.to_bytes().unwrap())
                    .await
                    .unwrap();
                assert_eq!(alice.get_conversation_unchecked(&id).await.members().len(), 2);
                bob_central
                    .conversation(&id)
                    .await
                    .unwrap()
                    .decrypt_message(commit.to_bytes().unwrap())
                    .await
                    .unwrap();
                assert!(alice.try_talk_to(&id, &charlie).await.is_ok());
                assert!(alice.try_talk_to(&id, &bob).await.is_err());
            })
            .await
        }

        #[apply(all_cred_cipher)]
        #[wasm_bindgen_test]
        async fn joiners_from_external_commit_can_accept_external_remove_proposals(case: TestContext) {
            let [alice, bob, charlie, ds] = case.sessions().await;
            Box::pin(async move {
                let alice_central = &alice.transaction;
                let bob_central = &bob.transaction;
                let charlie_central = &charlie.transaction;
                let id = conversation_id();

                let ds_signature_key = ds.client_signature_key(&case).await.as_slice().to_vec();
                let mut cfg = case.cfg.clone();
                alice_central
                    .set_raw_external_senders(&mut cfg, vec![ds_signature_key])
                    .await
                    .unwrap();

                alice_central
                    .new_conversation(&id, case.credential_type, cfg)
                    .await
                    .unwrap();

                alice.invite_all(&case, &id, [&bob]).await.unwrap();
                assert_eq!(alice.get_conversation_unchecked(&id).await.members().len(), 2);

                // Charlie joins through an external commit and should get external_senders
                // from PGS and not from configuration
                let public_group_state = alice.get_group_info(&id).await;
                charlie_central
                    .join_by_external_commit(public_group_state, case.custom_cfg(), case.credential_type)
                    .await
                    .unwrap();
                let commit = charlie.mls_transport().await.latest_commit().await;

                // Purposely have a configuration without `external_senders`
                alice_central
                    .conversation(&id)
                    .await
                    .unwrap()
                    .decrypt_message(commit.to_bytes().unwrap())
                    .await
                    .unwrap();
                bob_central
                    .conversation(&id)
                    .await
                    .unwrap()
                    .decrypt_message(commit.to_bytes().unwrap())
                    .await
                    .unwrap();

                assert_eq!(charlie.get_conversation_unchecked(&id).await.members().len(), 3);
                assert!(charlie.try_talk_to(&id, &alice).await.is_ok());
                assert!(charlie.try_talk_to(&id, &bob).await.is_ok());

                // now, as e.g. a Delivery Service, let's create an external remove proposal
                // and kick Bob out of the conversation
                let to_remove = alice.index_of(&id, bob.get_client_id().await).await;
                let sender_index = SenderExtensionIndex::new(0);
                let (sc, ct) = (case.signature_scheme(), case.credential_type);
                let cb = ds.find_most_recent_credential_bundle(sc, ct).await.unwrap();
                let group_id = GroupId::from_slice(&id[..]);
                let epoch = alice.get_conversation_unchecked(&id).await.group.epoch();
                let proposal =
                    ExternalProposal::new_remove(to_remove, group_id, epoch, &cb.signature_key, sender_index).unwrap();

                // joiner from external commit should be able to verify the external remove proposal
                // since it has fetched back the external_sender from external commit
                let charlie_can_verify_ext_proposal = charlie_central
                    .conversation(&id)
                    .await
                    .unwrap()
                    .decrypt_message(proposal.to_bytes().unwrap())
                    .await;
                assert!(charlie_can_verify_ext_proposal.is_ok());

                alice_central
                    .conversation(&id)
                    .await
                    .unwrap()
                    .decrypt_message(proposal.to_bytes().unwrap())
                    .await
                    .unwrap();
                bob_central
                    .conversation(&id)
                    .await
                    .unwrap()
                    .decrypt_message(proposal.to_bytes().unwrap())
                    .await
                    .unwrap();

                charlie_central
                    .conversation(&id)
                    .await
                    .unwrap()
                    .commit_pending_proposals()
                    .await
                    .unwrap();
                assert_eq!(charlie.get_conversation_unchecked(&id).await.members().len(), 2);

                let commit = charlie.mls_transport().await.latest_commit().await;
                alice_central
                    .conversation(&id)
                    .await
                    .unwrap()
                    .decrypt_message(commit.to_bytes().unwrap())
                    .await
                    .unwrap();
                assert_eq!(alice.get_conversation_unchecked(&id).await.members().len(), 2);
                bob_central
                    .conversation(&id)
                    .await
                    .unwrap()
                    .decrypt_message(commit.to_bytes().unwrap())
                    .await
                    .unwrap();
                assert!(alice.try_talk_to(&id, &charlie).await.is_ok());
                assert!(alice.try_talk_to(&id, &bob).await.is_err());
            })
            .await
        }
    }
}
