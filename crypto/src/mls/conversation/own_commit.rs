use super::{Error, Result};
use crate::{
    RecursiveError,
    mls::credential::{
        crl::{extract_crl_uris_from_group, get_new_crl_distribution_points},
        ext::CredentialExt,
    },
    prelude::{MlsConversation, MlsConversationDecryptMessage, Session},
};
use mls_crypto_provider::MlsCryptoProvider;
use openmls::prelude::{
    ConfirmationTag, ContentType, CredentialWithKey, FramedContentBodyIn, MlsMessageIn, MlsMessageInBody, Sender,
};

impl MlsConversation {
    /// Returns the confirmation tag from a public message that is an own commit.
    /// Returns an error if the confirmation tag in the own commit is missing.
    pub(crate) fn extract_confirmation_tag_from_own_commit<'a>(
        &self,
        own_commit: &'a MlsMessageIn,
    ) -> Result<&'a ConfirmationTag> {
        if let MlsMessageInBody::PublicMessage(msg) = own_commit.body_as_ref() {
            let is_commit = matches!(msg.content_type(), ContentType::Commit);
            let own_index = self.group.own_leaf_index();
            let is_self_sent = matches!(msg.sender(), Sender::Member(i) if i == &own_index);
            let is_own_commit = is_commit && is_self_sent;

            assert!(
                is_own_commit,
                "extract_confirmation_tag_from_own_commit() must always be called with an own commit."
            );
            assert!(
                matches!(msg.body(), FramedContentBodyIn::Commit(_)),
                "extract_confirmation_tag_from_own_commit() must always be called with an own commit."
            );

            msg.auth
                .confirmation_tag
                .as_ref()
                .ok_or(Error::MlsMessageInvalidState("Message confirmation tag not present"))
        } else {
            panic!(
                "extract_confirmation_tag_from_own_commit() must always be called \
                 with an MlsMessageIn containing an MlsMessageInBody::PublicMessage"
            );
        }
    }

    pub(crate) async fn handle_own_commit(
        &mut self,
        client: &Session,
        backend: &MlsCryptoProvider,
        ct: &ConfirmationTag,
    ) -> Result<MlsConversationDecryptMessage> {
        if self.group.pending_commit().is_none() {
            // This either means the DS replayed one of our commit OR we cleared a commit accepted by the DS
            // In both cases, CoreCrypto cannot be of any help since it cannot decrypt self commits
            // => deflect this case and let the caller handle it
            return Err(Error::SelfCommitIgnored);
        }

        if !self.eq_pending_commit(ct) {
            // this would mean we created a commit that got accepted by the DS but we cleared it locally
            // then somehow retried and created another commit. This is a manifest client error
            // and should be identified as such
            return Err(Error::ClearingPendingCommitError);
        }

        // incoming is from ourselves and it's the same as the local pending commit
        // => merge the pending commit & continue
        self.merge_pending_commit(client, backend).await
    }

    /// Compare incoming commit with local pending commit
    pub(crate) fn eq_pending_commit(&self, commit_ct: &ConfirmationTag) -> bool {
        if let Some(pending_commit) = self.group.pending_commit() {
            return pending_commit.get_confirmation_tag() == commit_ct;
        }
        false
    }

    /// When the incoming commit is sent by ourselves and it's the same as the local pending commit.
    /// This adapts [Self::commit_accepted] to return the same as [MlsConversation::decrypt_message]
    pub(crate) async fn merge_pending_commit(
        &mut self,
        client: &Session,
        backend: &MlsCryptoProvider,
    ) -> Result<MlsConversationDecryptMessage> {
        self.commit_accepted(client, backend).await?;

        let own_leaf = self
            .group
            .own_leaf()
            .ok_or(Error::MlsGroupInvalidState("own_leaf is None"))?;

        // We return self identity here, probably not necessary to check revocation
        let own_leaf_credential_with_key = CredentialWithKey {
            credential: own_leaf.credential().clone(),
            signature_key: own_leaf.signature_key().clone(),
        };
        let identity = own_leaf_credential_with_key
            .extract_identity(self.ciphersuite(), None)
            .map_err(RecursiveError::mls_credential("extracting identity"))?;

        let crl_new_distribution_points = get_new_crl_distribution_points(
            backend,
            extract_crl_uris_from_group(&self.group)
                .map_err(RecursiveError::mls_credential("extracting crl uris from group"))?,
        )
        .await
        .map_err(RecursiveError::mls_credential("getting new crl distribution points"))?;

        // we still support the `has_epoch_changed` field, though we'll remove it later
        #[expect(deprecated)]
        Ok(MlsConversationDecryptMessage {
            app_msg: None,
            proposals: vec![],
            is_active: self.group.is_active(),
            delay: self.compute_next_commit_delay(),
            sender_client_id: None,
            has_epoch_changed: true,
            identity,
            buffered_messages: None,
            crl_new_distribution_points,
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::test_utils::*;
    use openmls::prelude::{ProcessMessageError, ValidationError};

    use super::super::error::Error;
    use crate::prelude::MlsError;

    use crate::mls::conversation::Conversation as _;

    // If there’s a pending commit & it matches the incoming commit: mark pending commit as accepted
    #[apply(all_cred_cipher)]
    pub async fn should_succeed_when_incoming_commit_same_as_pending(case: TestContext) {
        if case.is_pure_ciphertext() || case.is_basic() {
            return;
        }
        let [alice] = case.sessions().await;
        Box::pin(async move {
            let x509_test_chain = alice.x509_chain_unchecked();

            let conversation = case.create_conversation([&alice]).await;

            assert!(!conversation.has_pending_commit().await);
            let epoch = conversation.guard().await.epoch().await;

            let intermediate_ca = x509_test_chain.find_local_intermediate_ca();

            // In this case Alice will try to rotate her credential but her commit will be denied
            // by the backend (because another commit from Bob had precedence)

            // Alice creates a new Credential, updating her handle/display_name
            let (new_handle, new_display_name) = ("new_alice_wire", "New Alice Smith");
            let cb = alice
                .save_new_credential(&case, new_handle, new_display_name, intermediate_ca)
                .await;

            // create a commit. This will also store it in the store
            let commit_guard = conversation.e2ei_rotate_unmerged(&cb).await;
            assert!(commit_guard.conversation().has_pending_commit().await);

            // since the pending commit is the same as the incoming one, it should succeed
            let conversation = commit_guard.notify_members_and_verify_sender().await;

            let epoch_after_decrypt = conversation.guard().await.epoch().await;
            assert_eq!(epoch + 1, epoch_after_decrypt);

            // there is no proposals to renew here since it's our own commit we merge
            assert!(!conversation.has_pending_proposals().await);

            // verify that we return the new identity
            alice
                .verify_local_credential_rotated(conversation.id(), new_handle, new_display_name)
                .await;
        })
        .await
    }

    // If there’s a pending commit & it does not match the self incoming commit: fail with dedicated error
    #[apply(all_cred_cipher)]
    pub async fn should_succeed_when_incoming_commit_mismatches_pending_commit(case: TestContext) {
        if case.is_pure_ciphertext() {
            return;
        }
        let [alice] = case.sessions().await;
        Box::pin(async move {
            let conversation = case.create_conversation([&alice]).await;

            assert!(!conversation.has_pending_commit().await);

            // create a first commit then discard it from the store to be able to create a second one
            let commit_guard = conversation.update_unmerged().await;
            let unmerged_commit = commit_guard.message();
            assert!(commit_guard.conversation().has_pending_commit().await);
            let conversation = commit_guard.finish();
            conversation.guard().await.clear_pending_commit().await.unwrap();
            assert!(!conversation.has_pending_commit().await);

            // create another commit for the sole purpose of having it in the store
            let commit_guard = conversation.update_unmerged().await;
            let unmerged_commit2 = commit_guard.message();
            assert_ne!(unmerged_commit, unmerged_commit2);
            let conversation = commit_guard.finish();

            let decrypt = conversation
                .guard()
                .await
                .decrypt_message(&unmerged_commit.to_bytes().unwrap())
                .await;
            assert!(matches!(decrypt.unwrap_err(), Error::ClearingPendingCommitError));
        })
        .await
    }

    // if there’s no pending commit & and the incoming commit originates from self: succeed by ignoring the incoming commit
    #[apply(all_cred_cipher)]
    pub async fn should_ignore_self_incoming_commit_when_no_pending_commit(case: TestContext) {
        if case.is_pure_ciphertext() {
            return;
        }
        let [alice] = case.sessions().await;
        Box::pin(async move {
            let conversation = case.create_conversation([&alice]).await;

            assert!(!conversation.has_pending_commit().await);

            // create a commit, have it in store...
            let commit_guard = conversation.update_unmerged().await;
            let conversation = commit_guard.conversation();
            assert!(conversation.has_pending_commit().await);

            // then delete the pending commit
            conversation.guard().await.clear_pending_commit().await.unwrap();
            assert!(!conversation.has_pending_commit().await);

            let (_, decrypt_self) = commit_guard.notify_member_fallible(&alice).await;
            // this means DS replayed the commit. In that case just ignore, we have already merged the commit anyway
            assert!(matches!(decrypt_self.unwrap_err(), Error::SelfCommitIgnored));
        })
        .await
    }

    #[apply(all_cred_cipher)]
    pub async fn should_fail_when_tampering_with_incoming_own_commit_same_as_pending(case: TestContext) {
        use crate::MlsErrorKind;

        if case.is_pure_ciphertext() {
            // The use case tested here requires inspecting your own commit.
            // Openmls does not support this currently when protocol messages are encrypted.
            return;
        }

        let [alice] = case.sessions().await;
        let conversation = case.create_conversation([&alice]).await;
        Box::pin(async move {
            // No pending commit yet.
            assert!(!conversation.has_pending_commit().await);

            // Create the commit that we're going to tamper with.
            let commit_guard = conversation.update_unmerged().await;
            let add_bob_message = commit_guard.message();
            let conversation = commit_guard.conversation();

            // Now there is a pending commit.
            assert!(conversation.has_pending_commit().await);

            let commit_serialized = &mut add_bob_message.to_bytes().unwrap();

            // Tamper with the commit; this is the signature region, however,
            // the membership tag covers the signature, so this will result in an
            // invalid membership tag error emitted by openmls.
            commit_serialized[300] = commit_serialized[300].wrapping_add(1);

            let decryption_result = conversation.guard().await.decrypt_message(commit_serialized).await;
            let error = decryption_result.unwrap_err();
            assert!(matches!(
                error,
                Error::Mls(MlsError {
                    source: MlsErrorKind::MlsMessageError(ProcessMessageError::ValidationError(
                        ValidationError::InvalidMembershipTag
                    )),
                    ..
                })
            ));

            // There is still a pending commit.
            assert!(conversation.has_pending_commit().await);

            // Positive case: Alice decrypts the commit...
            assert!(
                conversation
                    .guard()
                    .await
                    .decrypt_message(&add_bob_message.to_bytes().unwrap())
                    .await
                    .is_ok()
            );

            // ...and has cleared the pending commit.
            assert!(!conversation.has_pending_commit().await);
        })
        .await
    }

    #[apply(all_cred_cipher)]
    async fn should_succeed_when_incoming_commit_is_self_commit_but_was_lost(case: TestContext) {
        if case.is_pure_ciphertext() {
            // The use case tested here requires inspecting your own commit.
            // Openmls does not support this currently when protocol messages are encrypted.
            return;
        }

        Box::pin(async move {
            let [mut alice, bob] = case.sessions().await;
            let conversation = case.create_conversation([&alice, &bob]).await;
            let conversation_id = conversation.id().to_owned();

            drop(conversation);
            // Commit the transaction here; this is the state alice will be in when reloading the app after crashing.
            alice.commit_transaction().await;
            let conversation =
                TestConversation::new_from_existing(&case, conversation_id.clone(), [&alice, &bob]).await;

            // Alice creates a commit but won't merge it immediately.
            // In the meantime, Bob merges that commit.
            let commit_guard = conversation.update_unmerged().await.notify_member(&bob).await;
            let unmerged_commit = commit_guard.message().to_bytes().unwrap();
            let _conversation = commit_guard.finish();

            // Alice's app may have crashed, for example, before receiving the success response from the DS.
            // Crash happens here; changes since the transaction commit are not persisted.
            alice.pretend_crash().await;

            // ok, alice is back, and look: here's that commit that she made
            alice
                .transaction
                .conversation(&conversation_id)
                .await
                .unwrap()
                .decrypt_message(&unmerged_commit)
                .await
                .unwrap_err();
            //  .unwrap();
            //
            // We _want_ this case to work, and spent some effort attempting to make it work, but ultimately
            // couldn't figure out how to make it work given the OpenMLS primitives available. Ref: [WPB-17464].
            return;

            #[expect(unreachable_code)]
            {
                // mls is still healthy and Alice and Bob can still chat
                assert!(conversation.is_functional_and_contains([&alice, &bob]).await);
            }
        })
        .await
    }
}
