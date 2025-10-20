use openmls::prelude::{GroupEpoch, GroupId, JoinProposal, MlsMessageOut};

use super::Result;
use crate::{
    Ciphersuite, ConversationId, LeafError, MlsError, RecursiveError,
    mls::{self, credential::typ::MlsCredentialType},
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
        ciphersuite: Ciphersuite,
        credential_type: MlsCredentialType,
    ) -> Result<MlsMessageOut> {
        let group_id = GroupId::from_slice(conversation_id.as_ref());
        let mls_provider = self
            .mls_provider()
            .await
            .map_err(RecursiveError::transaction("getting mls provider"))?;

        let client = self
            .session()
            .await
            .map_err(RecursiveError::transaction("getting mls client"))?;
        let cb = client
            .find_most_recent_credential(ciphersuite.signature_algorithm(), credential_type)
            .await;
        let cb = match (cb, credential_type) {
            (Ok(cb), _) => cb,
            (Err(mls::session::Error::CredentialNotFound(_)), MlsCredentialType::Basic) => {
                // If a Basic Credential does not exist, just create one instead of failing
                client
                    .init_basic_credential_if_missing(&mls_provider, ciphersuite.signature_algorithm())
                    .await
                    .map_err(RecursiveError::mls_client("initializing basic credential if missing"))?;

                client
                    .find_most_recent_credential(ciphersuite.signature_algorithm(), credential_type)
                    .await
                    .map_err(RecursiveError::mls_client(
                        "finding most recent credential (which we just created)",
                    ))?
            }
            (Err(mls::session::Error::CredentialNotFound(_)), MlsCredentialType::X509) => {
                return Err(LeafError::E2eiEnrollmentNotDone.into());
            }
            (Err(e), _) => return Err(RecursiveError::mls_client("finding most recent credential")(e).into()),
        };
        let kp = client
            .generate_one_keypackage_from_credential(&mls_provider, ciphersuite, &cb)
            .await
            .map_err(RecursiveError::mls_client("generating one keypackage from credential"))?;

        JoinProposal::new(kp, group_id, epoch, &cb.signature_key_pair)
            .map_err(MlsError::wrap("creating join proposal"))
            .map_err(Into::into)
    }
}

#[cfg(test)]
mod tests {
    use crate::test_utils::*;

    mod add {
        use super::*;

        #[apply(all_cred_cipher)]
        async fn guest_should_externally_propose_adding_itself_to_owner_group(case: TestContext) {
            let [owner, guest] = case.sessions().await;
            Box::pin(async move {
                let conversation = case.create_conversation([&owner]).await;

                // Craft an external proposal from guest
                // Owner receives external proposal message from server
                let (proposal_guard, decrypted) = conversation
                    .external_join_proposal(&guest)
                    .await
                    .notify_member_fallible(&owner)
                    .await;
                let conversation = proposal_guard.finish();
                // just owner for now
                assert_eq!(conversation.member_count().await, 1);

                // verify Guest's (sender) identity
                guest.verify_sender_identity(&case, &decrypted.unwrap()).await;

                // simulate commit message reception from server
                let conversation = conversation.commit_pending_proposals_notify().await;
                // guest joined the group
                assert_eq!(conversation.member_count().await, 2);

                // guest can send messages in the group
                assert!(conversation.is_functional_and_contains([&owner, &guest]).await);
            })
            .await
        }
    }

    mod remove {
        use openmls::prelude::{ProcessMessageError, ValidationError};

        use super::*;
        use crate::{MlsError, MlsErrorKind};

        #[apply(all_cred_cipher)]
        async fn ds_should_remove_guest_from_conversation(mut case: TestContext) {
            let [owner, guest, ds] = case.sessions().await;
            Box::pin(async move {
                let conversation = case
                    .create_conversation_with_external_sender(&ds, [&owner, &guest])
                    .await;
                assert_eq!(conversation.member_count().await, 2);

                // now, as e.g. a Delivery Service, let's create an external remove proposal
                // and kick guest out of the conversation

                let conversation = conversation.external_remove_proposal_notify(&ds, &guest).await;
                let conversation = conversation.commit_pending_proposals_notify().await;
                assert_eq!(conversation.member_count().await, 1);

                // guest can no longer participate
                assert!(guest.transaction.conversation(conversation.id()).await.is_err());
                assert!(!conversation.can_talk(&owner, &guest).await);
            })
            .await
        }

        #[apply(all_cred_cipher)]
        async fn should_fail_when_invalid_external_sender(mut case: TestContext) {
            use crate::mls;

            let [owner, guest, ds, attacker] = case.sessions().await;
            Box::pin(async move {
                // Delivery service key is used in the group..
                let conversation = case
                    .create_conversation_with_external_sender(&ds, [&owner, &guest])
                    .await;
                assert_eq!(conversation.member_count().await, 2);

                // now, attacker will try to remove guest from the group, and should fail
                let proposal_guard = conversation
                    .external_remove_proposal_with_sender_index(&attacker, 1, &guest)
                    .await;

                let (proposal_guard, owner_decrypt) = proposal_guard.notify_member_fallible(&owner).await;

                assert!(matches!(
                    owner_decrypt.unwrap_err(),
                    mls::conversation::Error::Mls(MlsError {
                        source: MlsErrorKind::MlsMessageError(ProcessMessageError::ValidationError(
                            ValidationError::UnauthorizedExternalSender
                        )),
                        ..
                    })
                ));

                let (_, guest_decrypt) = proposal_guard.notify_member_fallible(&guest).await;
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
        async fn should_fail_when_wrong_signature_key(mut case: TestContext) {
            use crate::mls;

            let [owner, guest, ds] = case.sessions().await;
            Box::pin(async move {
                // Here we're going to add the Delivery Service's (DS) signature key to the
                // external senders list. However, for the purpose of this test, we will
                // intentionally _not_ use that key when generating the remove proposal below.
                let conversation = case
                    .create_conversation_with_external_sender(&ds, [&owner, &guest])
                    .await;
                assert_eq!(conversation.member_count().await, 2);

                // Intentionally use the guest's credential, and therefore the guest's signature
                // key when generating the proposal so that the signature verification fails.
                let proposal_guard = conversation.external_remove_proposal(&guest, &guest).await;

                let (proposal_guard, owner_decrypt) = proposal_guard.notify_member_fallible(&owner).await;
                assert!(matches!(
                    owner_decrypt.unwrap_err(),
                    mls::conversation::Error::Mls(MlsError {
                        source: MlsErrorKind::MlsMessageError(ProcessMessageError::InvalidSignature),
                        ..
                    })
                ));

                let (_, guest_decrypt) = proposal_guard.notify_member_fallible(&guest).await;
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
        async fn joiners_from_welcome_can_accept_external_remove_proposals(mut case: TestContext) {
            let [alice, bob, charlie, ds] = case.sessions().await;
            Box::pin(async move {
                let conversation = case.create_conversation_with_external_sender(&ds, [&alice, &bob]).await;
                assert_eq!(conversation.member_count().await, 2);

                // Charlie joins through a Welcome and should get external_senders from Welcome
                // message and not from configuration
                // charlie can only get it from there, because the `MlsCustomgConfiguration` that they receive when processing
                // the welcome, doesn't contain any info about an external sender.
                let conversation = conversation.invite_notify([&charlie]).await;
                assert_eq!(conversation.member_count().await, 3);
                assert!(conversation.is_functional_and_contains([&alice, &bob, &charlie]).await);

                // now, as e.g. a Delivery Service, let's create an external remove proposal
                // and kick Bob out of the conversation

                // joiner from Welcome should be able to verify the external remove proposal since
                // it has fetched back the external_sender from Welcome
                let conversation = conversation.external_remove_proposal_notify(&ds, &bob).await;
                let conversation = conversation
                    .acting_as(&charlie)
                    .await
                    .commit_pending_proposals_notify()
                    .await;

                assert_eq!(conversation.member_count().await, 2);

                assert!(conversation.is_functional_and_contains([&alice, &charlie]).await);
                assert!(!conversation.can_talk(&alice, &bob).await);
            })
            .await
        }

        #[apply(all_cred_cipher)]
        async fn joiners_from_external_commit_can_accept_external_remove_proposals(mut case: TestContext) {
            let [alice, bob, charlie, ds] = case.sessions().await;
            Box::pin(async move {
                let conversation = case.create_conversation_with_external_sender(&ds, [&alice, &bob]).await;
                assert_eq!(conversation.member_count().await, 2);

                // Charlie joins through an external commit and should get external_senders
                // from the public group state and not from configuration
                let conversation = conversation.external_join_notify(&charlie).await;
                assert_eq!(conversation.member_count().await, 3);
                assert!(conversation.is_functional_and_contains([&alice, &bob, &charlie]).await);

                // now, as e.g. a Delivery Service, let's create an external remove proposal
                // and kick Bob out of the conversation

                // joiner from external commit should be able to verify the external remove proposal
                // since it has fetched back the external_sender from external commit
                let conversation = conversation.external_remove_proposal_notify(&ds, &bob).await;
                let conversation = conversation
                    .acting_as(&charlie)
                    .await
                    .commit_pending_proposals_notify()
                    .await;

                assert_eq!(conversation.member_count().await, 2);

                assert!(conversation.is_functional_and_contains([&alice, &charlie]).await);
                assert!(!conversation.can_talk(&alice, &bob).await);
            })
            .await
        }
    }
}
