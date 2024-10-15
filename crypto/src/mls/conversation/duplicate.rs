//! Due the current delivery semantics on backend side (at least once) we have to deal with this
//! in CoreCrypto so as not to return a decryption error to the client. Remove this when this is used
//! with a DS guaranteeing exactly once delivery semantics since the following degrades the performances

use crate::prelude::MlsConversation;
use crate::{CryptoError, MlsError};
use mls_crypto_provider::TransactionalCryptoProvider;
use openmls::prelude::{ContentType, FramedContentBodyIn, Proposal, PublicMessageIn, Sender};

impl MlsConversation {
    pub(crate) fn is_duplicate_message(
        &self,
        backend: &TransactionalCryptoProvider,
        msg: &PublicMessageIn,
    ) -> Result<bool, CryptoError> {
        let (sender, content_type) = (msg.sender(), msg.body().content_type());

        match (content_type, sender) {
            (ContentType::Commit, Sender::Member(_) | Sender::NewMemberCommit) => {
                // we use the confirmation tag to detect duplicate since it is issued from the GroupContext
                // which is supposed to be unique per epoch
                if let Some(msg_ct) = msg.confirmation_tag() {
                    let group_ct = self.group.compute_confirmation_tag(backend).map_err(MlsError::from)?;
                    Ok(msg_ct == &group_ct)
                } else {
                    // a commit MUST have a ConfirmationTag
                    Err(CryptoError::InternalMlsError)
                }
            }
            (ContentType::Proposal, Sender::Member(_) | Sender::NewMemberProposal) => {
                match msg.body() {
                    FramedContentBodyIn::Proposal(proposal) => {
                        let proposal = Proposal::from(proposal.clone()); // TODO: eventually remove this clone 😮‍💨. Tracking issue: WPB-9622
                        let already_exists = self.group.pending_proposals().any(|pp| pp.proposal() == &proposal);
                        Ok(already_exists)
                    }
                    _ => Err(CryptoError::InternalMlsError),
                }
            }
            (_, _) => Ok(false),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{test_utils::*, CryptoError};
    use wasm_bindgen_test::*;

    wasm_bindgen_test_configure!(run_in_browser);

    #[apply(all_cred_cipher)]
    #[wasm_bindgen_test]
    async fn decrypting_duplicate_member_commit_should_fail(case: TestCase) {
        // cannot work in pure ciphertext since we'd have to decrypt the message first
        if !case.is_pure_ciphertext() {
            run_test_with_client_ids(
                case.clone(),
                ["alice", "bob"],
                move |[alice_central, bob_central]| {
                    Box::pin(async move {
                        let id = conversation_id();
                        alice_central
                            .context
                            .new_conversation(&id, case.credential_type, case.cfg.clone())
                            .await
                            .unwrap();
                        alice_central
                            .invite_all(&case, &id, [&bob_central])
                            .await
                            .unwrap();

                        // an commit to verify that we can still detect wrong epoch correctly
                        let unknown_commit = alice_central.context.update_keying_material(&id).await.unwrap().commit;
                        alice_central.context.clear_pending_commit(&id).await.unwrap();

                        let commit = alice_central.context.update_keying_material(&id).await.unwrap().commit;
                        alice_central.context.commit_accepted(&id).await.unwrap();

                        // decrypt once ... ok
                        bob_central
                            .context
                            .decrypt_message(&id, &commit.to_bytes().unwrap())
                            .await
                            .unwrap();
                        // decrypt twice ... not ok
                        let decrypt_duplicate = bob_central
                            .context
                            .decrypt_message(&id, &commit.to_bytes().unwrap())
                            .await;
                        assert!(matches!(decrypt_duplicate.unwrap_err(), CryptoError::DuplicateMessage));

                        // Decrypting unknown commit.
                        // It fails with this error since it's not the commit who has created this epoch
                        let decrypt_lost_commit = bob_central
                            .context
                            .decrypt_message(&id, &unknown_commit.to_bytes().unwrap())
                            .await;
                        assert!(matches!(decrypt_lost_commit.unwrap_err(), CryptoError::StaleCommit));
                    })
                },
            )
            .await
        }
    }

    #[apply(all_cred_cipher)]
    #[wasm_bindgen_test]
    async fn decrypting_duplicate_external_commit_should_fail(case: TestCase) {
        run_test_with_client_ids(
            case.clone(),
            ["alice", "bob"],
            move |[alice_central, bob_central]| {
                Box::pin(async move {
                    let id = conversation_id();
                    alice_central
                        .context
                        .new_conversation(&id, case.credential_type, case.cfg.clone())
                        .await
                        .unwrap();

                    let gi = alice_central.get_group_info(&id).await;

                    // an external commit to verify that we can still detect wrong epoch correctly
                    let unknown_ext_commit = bob_central
                        .context
                        .join_by_external_commit(gi.clone(), case.custom_cfg(), case.credential_type)
                        .await
                        .unwrap()
                        .commit;
                    bob_central
                        .context
                        .clear_pending_group_from_external_commit(&id)
                        .await
                        .unwrap();

                    let ext_commit = bob_central
                        .context
                        .join_by_external_commit(gi, case.custom_cfg(), case.credential_type)
                        .await
                        .unwrap()
                        .commit;
                    bob_central
                        .context
                        .merge_pending_group_from_external_commit(&id)
                        .await
                        .unwrap();

                    // decrypt once ... ok
                    alice_central
                        .context
                        .decrypt_message(&id, &ext_commit.to_bytes().unwrap())
                        .await
                        .unwrap();
                    // decrypt twice ... not ok
                    let decryption = alice_central
                        .context
                        .decrypt_message(&id, &ext_commit.to_bytes().unwrap())
                        .await;
                    assert!(matches!(decryption.unwrap_err(), CryptoError::DuplicateMessage));

                    // Decrypting unknown external commit.
                    // It fails with this error since it's not the external commit who has created this epoch
                    let decryption = alice_central
                        .context
                        .decrypt_message(&id, &unknown_ext_commit.to_bytes().unwrap())
                        .await;
                    assert!(matches!(decryption.unwrap_err(), CryptoError::StaleCommit));
                })
            },
        )
        .await
    }

    #[apply(all_cred_cipher)]
    #[wasm_bindgen_test]
    async fn decrypting_duplicate_proposal_should_fail(case: TestCase) {
        run_test_with_client_ids(
            case.clone(),
            ["alice", "bob"],
            move |[alice_central, bob_central]| {
                Box::pin(async move {
                    let id = conversation_id();
                    alice_central
                        .context
                        .new_conversation(&id, case.credential_type, case.cfg.clone())
                        .await
                        .unwrap();
                    alice_central
                        .invite_all(&case, &id, [&bob_central])
                        .await
                        .unwrap();

                    let proposal = alice_central.context.new_update_proposal(&id).await.unwrap().proposal;

                    // decrypt once ... ok
                    bob_central
                        .context
                        .decrypt_message(&id, &proposal.to_bytes().unwrap())
                        .await
                        .unwrap();

                    // decrypt twice ... not ok
                    let decryption = bob_central
                        .context
                        .decrypt_message(&id, &proposal.to_bytes().unwrap())
                        .await;
                    assert!(matches!(decryption.unwrap_err(), CryptoError::DuplicateMessage));

                    // advance Bob's epoch to trigger failure
                    bob_central.context.commit_pending_proposals(&id).await.unwrap();
                    bob_central.context.commit_accepted(&id).await.unwrap();

                    // Epoch has advanced so we cannot detect duplicates anymore
                    let decryption = bob_central
                        .context
                        .decrypt_message(&id, &proposal.to_bytes().unwrap())
                        .await;
                    assert!(matches!(decryption.unwrap_err(), CryptoError::StaleProposal));
                })
            },
        )
        .await
    }

    #[apply(all_cred_cipher)]
    #[wasm_bindgen_test]
    async fn decrypting_duplicate_external_proposal_should_fail(case: TestCase) {
        run_test_with_client_ids(
            case.clone(),
            ["alice", "bob"],
            move |[alice_central, bob_central]| {
                Box::pin(async move {
                    let id = conversation_id();
                    alice_central
                        .context
                        .new_conversation(&id, case.credential_type, case.cfg.clone())
                        .await
                        .unwrap();

                    let epoch = alice_central.context.conversation_epoch(&id).await.unwrap();

                    let ext_proposal = bob_central
                        .context
                        .new_external_add_proposal(id.clone(), epoch.into(), case.ciphersuite(), case.credential_type)
                        .await
                        .unwrap();

                    // decrypt once ... ok
                    alice_central
                        .context
                        .decrypt_message(&id, &ext_proposal.to_bytes().unwrap())
                        .await
                        .unwrap();

                    // decrypt twice ... not ok
                    let decryption = alice_central
                        .context
                        .decrypt_message(&id, &ext_proposal.to_bytes().unwrap())
                        .await;
                    assert!(matches!(decryption.unwrap_err(), CryptoError::DuplicateMessage));

                    // advance alice's epoch
                    alice_central.context.commit_pending_proposals(&id).await.unwrap();
                    alice_central.context.commit_accepted(&id).await.unwrap();

                    // Epoch has advanced so we cannot detect duplicates anymore
                    let decryption = alice_central
                        .context
                        .decrypt_message(&id, &ext_proposal.to_bytes().unwrap())
                        .await;
                    assert!(matches!(decryption.unwrap_err(), CryptoError::StaleProposal));
                })
            },
        )
        .await
    }

    // Ensures decrypting an application message is durable (we increment the messages generation & persist the group)
    #[apply(all_cred_cipher)]
    #[wasm_bindgen_test]
    async fn decrypting_duplicate_application_message_should_fail(case: TestCase) {
        run_test_with_client_ids(
            case.clone(),
            ["alice", "bob"],
            move |[alice_central, bob_central]| {
                Box::pin(async move {
                    let id = conversation_id();
                    alice_central
                        .context
                        .new_conversation(&id, case.credential_type, case.cfg.clone())
                        .await
                        .unwrap();
                    alice_central
                        .invite_all(&case, &id, [&bob_central])
                        .await
                        .unwrap();

                    let msg = b"Hello bob";
                    let encrypted = alice_central.context.encrypt_message(&id, msg).await.unwrap();

                    // decrypt once .. ok
                    bob_central.context.decrypt_message(&id, &encrypted).await.unwrap();
                    // decrypt twice .. not ok
                    let decryption = bob_central.context.decrypt_message(&id, &encrypted).await;
                    assert!(matches!(decryption.unwrap_err(), CryptoError::DuplicateMessage));
                })
            },
        )
        .await
    }
}
