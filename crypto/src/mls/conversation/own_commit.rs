use crate::{
    mls::credential::{
        crl::{extract_crl_uris_from_group, get_new_crl_distribution_points},
        ext::CredentialExt,
    },
    prelude::{CryptoError, CryptoResult, MlsConversation, MlsConversationDecryptMessage},
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
    ) -> CryptoResult<&'a ConfirmationTag> {
        match own_commit.body_as_ref() {
            MlsMessageInBody::PublicMessage(msg) => {
                let is_commit = matches!(msg.content_type(), ContentType::Commit);
                let own_index = self.group.own_leaf_index();
                let is_self_sent = matches!(msg.sender(), Sender::Member(i) if i == &own_index);
                let is_own_commit = is_commit && is_self_sent;

                match is_own_commit.then_some(msg.body()) {
                    Some(FramedContentBodyIn::Commit(_)) => {
                        let confirmation_tag = msg
                            .auth
                            .confirmation_tag
                            .as_ref()
                            .ok_or(CryptoError::InternalMlsError)?;
                        Ok(confirmation_tag)
                    }
                    // Not an own commit. Should never be reached if this function
                    // is called correctly.
                    _ => unreachable!(
                        "extract_confirmation_tag_from_own_commit() must always be called \
                        with a an own commit."
                    ),
                }
            }
            // Not a public message. Should never be reached if this function is called correctly.
            _ => unreachable!(
                "extract_confirmation_tag_from_own_commit() must always be called \
                 with an MlsMessageIn containing an MlsMessageInBody::PublicMessage"
            ),
        }
    }

    #[cfg_attr(not(test), tracing::instrument(skip_all, err))]
    pub(crate) async fn handle_own_commit<'a>(
        &mut self,
        backend: &MlsCryptoProvider,
        ct: &ConfirmationTag,
    ) -> CryptoResult<MlsConversationDecryptMessage> {
        if self.group.pending_commit().is_some() {
            if self.eq_pending_commit(ct) {
                // incoming is from ourselves and it's the same as the local pending commit
                // => merge the pending commit & continue
                self.merge_pending_commit(backend).await
            } else {
                // this would mean we created a commit that got accepted by the DS but we cleared it locally
                // then somehow retried and created another commit. This is a manifest client error
                // and should be identified as such
                Err(CryptoError::ClearingPendingCommitError)
            }
        } else {
            // This either means the DS replayed one of our commit OR we cleared a commit accepted by the DS
            // In both cases, CoreCrypto cannot be of any help since it cannot decrypt self commits
            // => deflect this case and let the caller handle it
            Err(CryptoError::SelfCommitIgnored)
        }
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
        backend: &MlsCryptoProvider,
    ) -> CryptoResult<MlsConversationDecryptMessage> {
        self.commit_accepted(backend).await?;

        let own_leaf = self.group.own_leaf().ok_or(CryptoError::InternalMlsError)?;

        // We return self identity here, probably not necessary to check revocation
        let own_leaf_credential_with_key = CredentialWithKey {
            credential: own_leaf.credential().clone(),
            signature_key: own_leaf.signature_key().clone(),
        };
        let identity = own_leaf_credential_with_key.extract_identity(self.ciphersuite(), None)?;

        let crl_new_distribution_points =
            get_new_crl_distribution_points(backend, extract_crl_uris_from_group(&self.group)?).await?;

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
    use crate::CryptoError;
    use wasm_bindgen_test::*;

    wasm_bindgen_test_configure!(run_in_browser);

    // If there’s a pending commit & it matches the incoming commit: mark pending commit as accepted
    #[apply(all_cred_cipher)]
    #[wasm_bindgen_test]
    pub async fn should_succeed_when_incoming_commit_same_as_pending(case: TestCase) {
        if !case.is_pure_ciphertext() && case.is_x509() {
            run_test_with_client_ids(case.clone(), ["alice"], move |[mut alice_central]| {
                Box::pin(async move {
                    let x509_test_chain = alice_central
                        .x509_test_chain
                        .as_ref()
                        .as_ref()
                        .expect("No x509 test chain");

                    let id = conversation_id();
                    alice_central
                        .mls_central
                        .new_conversation(&id, case.credential_type, case.cfg.clone())
                        .await
                        .unwrap();

                    assert!(alice_central.mls_central.pending_commit(&id).await.is_none());

                    let alice_og_cert = &x509_test_chain
                        .actors
                        .iter()
                        .find(|actor| actor.name == "alice")
                        .unwrap()
                        .certificate;

                    // change credential to verify later what we return in the decrypt message
                    let (new_handle, new_display_name) = ("new_alice_wire", "New Alice Smith");
                    let cb = alice_central
                        .mls_central
                        .rotate_credential(
                            &case,
                            new_handle,
                            new_display_name,
                            alice_og_cert,
                            x509_test_chain.find_local_intermediate_ca(),
                        )
                        .await;

                    // create a commit. This will also store it in the store
                    let commit = alice_central.mls_central.e2ei_rotate(&id, &cb).await.unwrap().commit;
                    assert!(alice_central.mls_central.pending_commit(&id).await.is_some());

                    // since the pending commit is the same as the incoming one, it should succeed
                    let decrypt_self = alice_central
                        .mls_central
                        .decrypt_message(&id, &commit.to_bytes().unwrap())
                        .await;
                    assert!(decrypt_self.is_ok());
                    let decrypt_self = decrypt_self.unwrap();

                    // there is no proposals to renew here since it's our own commit we merge
                    assert!(decrypt_self.proposals.is_empty());

                    // verify that we return the new identity
                    alice_central.mls_central.verify_sender_identity(&case, &decrypt_self);
                    alice_central
                        .mls_central
                        .verify_local_credential_rotated(&id, new_handle, new_display_name)
                        .await;
                })
            })
            .await
        }
    }

    // If there’s a pending commit & it does not match the self incoming commit: fail with dedicated error
    #[apply(all_cred_cipher)]
    #[wasm_bindgen_test]
    pub async fn should_succeed_when_incoming_commit_mismatches_pending_commit(case: TestCase) {
        if !case.is_pure_ciphertext() {
            run_test_with_client_ids(
                case.clone(),
                ["alice", "bob", "charlie"],
                move |[mut alice_central, bob_central, charlie_central]| {
                    Box::pin(async move {
                        let id = conversation_id();
                        alice_central
                            .mls_central
                            .new_conversation(&id, case.credential_type, case.cfg.clone())
                            .await
                            .unwrap();

                        assert!(alice_central.mls_central.pending_commit(&id).await.is_none());

                        let bob = bob_central.mls_central.rand_key_package(&case).await;
                        let charlie = charlie_central.mls_central.rand_key_package(&case).await;

                        // create a first commit then discard it from the store to be able to create a second one
                        let add_bob = alice_central
                            .mls_central
                            .add_members_to_conversation(&id, vec![bob])
                            .await
                            .unwrap();
                        assert!(alice_central.mls_central.pending_commit(&id).await.is_some());
                        alice_central.mls_central.clear_pending_commit(&id).await.unwrap();
                        assert!(alice_central.mls_central.pending_commit(&id).await.is_none());

                        // create another commit for the sole purpose of having it in the store
                        let add_charlie = alice_central
                            .mls_central
                            .add_members_to_conversation(&id, vec![charlie])
                            .await
                            .unwrap();
                        assert!(alice_central.mls_central.pending_commit(&id).await.is_some());
                        assert_ne!(add_bob.commit, add_charlie.commit);

                        let decrypt = alice_central
                            .mls_central
                            .decrypt_message(&id, &add_bob.commit.to_bytes().unwrap())
                            .await;
                        assert!(matches!(decrypt.unwrap_err(), CryptoError::ClearingPendingCommitError));
                    })
                },
            )
            .await
        }
    }

    // if there’s no pending commit & and the incoming commit originates from self: succeed by ignoring the incoming commit
    #[apply(all_cred_cipher)]
    #[wasm_bindgen_test]
    pub async fn should_ignore_self_incoming_commit_when_no_pending_commit(case: TestCase) {
        if !case.is_pure_ciphertext() {
            run_test_with_client_ids(case.clone(), ["alice"], move |[mut alice_central]| {
                Box::pin(async move {
                    let id = conversation_id();
                    alice_central
                        .mls_central
                        .new_conversation(&id, case.credential_type, case.cfg.clone())
                        .await
                        .unwrap();

                    assert!(alice_central.mls_central.pending_commit(&id).await.is_none());

                    // create a commit, have it in store...
                    let commit = alice_central
                        .mls_central
                        .update_keying_material(&id)
                        .await
                        .unwrap()
                        .commit;
                    assert!(alice_central.mls_central.pending_commit(&id).await.is_some());

                    // then delete the pending commit
                    alice_central.mls_central.clear_pending_commit(&id).await.unwrap();
                    assert!(alice_central.mls_central.pending_commit(&id).await.is_none());

                    let decrypt_self = alice_central
                        .mls_central
                        .decrypt_message(&id, &commit.to_bytes().unwrap())
                        .await;
                    // this means DS replayed the commit. In that case just ignore, we have already merged the commit anyway
                    assert!(matches!(decrypt_self.unwrap_err(), CryptoError::SelfCommitIgnored));
                })
            })
            .await
        }
    }
}
