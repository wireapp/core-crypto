//! Due the current delivery semantics on backend side (at least once) we have to deal with this
//! in CoreCrypto so as not to return a decryption error to the client. Remove this when this is used
//! with a DS guaranteeing exactly once delivery semantics since the following degrades the performances

use super::{Error, Result};
use crate::{MlsError, prelude::MlsConversation};
use mls_crypto_provider::MlsCryptoProvider;
use openmls::prelude::{ContentType, FramedContentBodyIn, Proposal, PublicMessageIn, Sender};

impl MlsConversation {
    pub(crate) fn is_duplicate_message(&self, backend: &MlsCryptoProvider, msg: &PublicMessageIn) -> Result<bool> {
        let (sender, content_type) = (msg.sender(), msg.body().content_type());

        match (content_type, sender) {
            (ContentType::Commit, Sender::Member(_) | Sender::NewMemberCommit) => {
                // we use the confirmation tag to detect duplicate since it is issued from the GroupContext
                // which is supposed to be unique per epoch
                if let Some(msg_ct) = msg.confirmation_tag() {
                    let group_ct = self
                        .group
                        .compute_confirmation_tag(backend)
                        .map_err(MlsError::wrap("computing confirmation tag"))?;
                    Ok(msg_ct == &group_ct)
                } else {
                    // a commit MUST have a ConfirmationTag
                    Err(Error::MlsGroupInvalidState("a commit must have a ConfirmationTag"))
                }
            }
            (ContentType::Proposal, Sender::Member(_) | Sender::NewMemberProposal) => {
                match msg.body() {
                    FramedContentBodyIn::Proposal(proposal) => {
                        let proposal = Proposal::from(proposal.clone()); // TODO: eventually remove this clone 😮‍💨. Tracking issue: WPB-9622
                        let already_exists = self.group.pending_proposals().any(|pp| pp.proposal() == &proposal);
                        Ok(already_exists)
                    }
                    _ => Err(Error::MlsGroupInvalidState(
                        "message body was not a proposal despite ContentType::Proposal",
                    )),
                }
            }
            (_, _) => Ok(false),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::error::Error;
    use crate::mls::conversation::Conversation as _;
    use crate::test_utils::*;
    use wasm_bindgen_test::*;

    wasm_bindgen_test_configure!(run_in_browser);

    #[apply(all_cred_cipher)]
    #[wasm_bindgen_test]
    async fn decrypting_duplicate_member_commit_should_fail(case: TestContext) {
        // cannot work in pure ciphertext since we'd have to decrypt the message first
        if !case.is_pure_ciphertext() {
            let [alice_central, bob_central] = case.sessions().await;
            Box::pin(async move {
                let id = conversation_id();
                alice_central
                    .transaction
                    .new_conversation(&id, case.credential_type, case.cfg.clone())
                    .await
                    .unwrap();
                alice_central.invite_all(&case, &id, [&bob_central]).await.unwrap();

                // an commit to verify that we can still detect wrong epoch correctly
                let unknown_commit = alice_central.create_unmerged_commit(&id).await.commit;
                alice_central
                    .transaction
                    .conversation(&id)
                    .await
                    .unwrap()
                    .clear_pending_commit()
                    .await
                    .unwrap();

                alice_central
                    .transaction
                    .conversation(&id)
                    .await
                    .unwrap()
                    .update_key_material()
                    .await
                    .unwrap();
                let commit = alice_central.mls_transport().await.latest_commit().await;

                // decrypt once ... ok
                bob_central
                    .transaction
                    .conversation(&id)
                    .await
                    .unwrap()
                    .decrypt_message(&commit.to_bytes().unwrap())
                    .await
                    .unwrap();
                // decrypt twice ... not ok
                let decrypt_duplicate = bob_central
                    .transaction
                    .conversation(&id)
                    .await
                    .unwrap()
                    .decrypt_message(&commit.to_bytes().unwrap())
                    .await;
                assert!(matches!(decrypt_duplicate.unwrap_err(), Error::DuplicateMessage));

                // Decrypting unknown commit.
                // It fails with this error since it's not the commit who has created this epoch
                let decrypt_lost_commit = bob_central
                    .transaction
                    .conversation(&id)
                    .await
                    .unwrap()
                    .decrypt_message(&unknown_commit.to_bytes().unwrap())
                    .await;
                assert!(matches!(decrypt_lost_commit.unwrap_err(), Error::StaleCommit));
            })
            .await
        }
    }

    #[apply(all_cred_cipher)]
    #[wasm_bindgen_test]
    async fn decrypting_duplicate_external_commit_should_fail(case: TestContext) {
        let [alice_central, bob_central] = case.sessions().await;
        Box::pin(async move {
            let id = conversation_id();
            alice_central
                .transaction
                .new_conversation(&id, case.credential_type, case.cfg.clone())
                .await
                .unwrap();

            let gi = alice_central.get_group_info(&id).await;

            // an external commit to verify that we can still detect wrong epoch correctly
            let (unknown_ext_commit, mut pending_conversation) = bob_central
                .create_unmerged_external_commit(gi.clone(), case.custom_cfg(), case.credential_type)
                .await;
            let unknown_ext_commit = unknown_ext_commit.commit;
            pending_conversation.clear().await.unwrap();

            bob_central
                .transaction
                .join_by_external_commit(gi, case.custom_cfg(), case.credential_type)
                .await
                .unwrap();
            let ext_commit = bob_central.mls_transport().await.latest_commit().await;

            // decrypt once ... ok
            alice_central
                .transaction
                .conversation(&id)
                .await
                .unwrap()
                .decrypt_message(&ext_commit.to_bytes().unwrap())
                .await
                .unwrap();
            // decrypt twice ... not ok
            let decryption = alice_central
                .transaction
                .conversation(&id)
                .await
                .unwrap()
                .decrypt_message(&ext_commit.to_bytes().unwrap())
                .await;
            assert!(matches!(decryption.unwrap_err(), Error::DuplicateMessage));

            // Decrypting unknown external commit.
            // It fails with this error since it's not the external commit who has created this epoch
            let decryption = alice_central
                .transaction
                .conversation(&id)
                .await
                .unwrap()
                .decrypt_message(&unknown_ext_commit.to_bytes().unwrap())
                .await;
            assert!(matches!(decryption.unwrap_err(), Error::StaleCommit));
        })
        .await
    }

    #[apply(all_cred_cipher)]
    #[wasm_bindgen_test]
    async fn decrypting_duplicate_proposal_should_fail(case: TestContext) {
        let [alice_central, bob_central] = case.sessions().await;
        Box::pin(async move {
            let id = conversation_id();
            alice_central
                .transaction
                .new_conversation(&id, case.credential_type, case.cfg.clone())
                .await
                .unwrap();
            alice_central.invite_all(&case, &id, [&bob_central]).await.unwrap();

            let proposal = alice_central
                .transaction
                .new_update_proposal(&id)
                .await
                .unwrap()
                .proposal;

            // decrypt once ... ok
            bob_central
                .transaction
                .conversation(&id)
                .await
                .unwrap()
                .decrypt_message(&proposal.to_bytes().unwrap())
                .await
                .unwrap();

            // decrypt twice ... not ok
            let decryption = bob_central
                .transaction
                .conversation(&id)
                .await
                .unwrap()
                .decrypt_message(&proposal.to_bytes().unwrap())
                .await;
            assert!(matches!(decryption.unwrap_err(), Error::DuplicateMessage));

            // advance Bob's epoch to trigger failure
            bob_central
                .transaction
                .conversation(&id)
                .await
                .unwrap()
                .commit_pending_proposals()
                .await
                .unwrap();

            // Epoch has advanced so we cannot detect duplicates anymore
            let decryption = bob_central
                .transaction
                .conversation(&id)
                .await
                .unwrap()
                .decrypt_message(&proposal.to_bytes().unwrap())
                .await;
            assert!(matches!(decryption.unwrap_err(), Error::StaleProposal));
        })
        .await
    }

    #[apply(all_cred_cipher)]
    #[wasm_bindgen_test]
    async fn decrypting_duplicate_external_proposal_should_fail(case: TestContext) {
        let [alice_central, bob_central] = case.sessions().await;
        Box::pin(async move {
            let id = conversation_id();
            alice_central
                .transaction
                .new_conversation(&id, case.credential_type, case.cfg.clone())
                .await
                .unwrap();

            let epoch = alice_central.transaction.conversation(&id).await.unwrap().epoch().await;

            let ext_proposal = bob_central
                .transaction
                .new_external_add_proposal(id.clone(), epoch.into(), case.ciphersuite(), case.credential_type)
                .await
                .unwrap();

            // decrypt once ... ok
            alice_central
                .transaction
                .conversation(&id)
                .await
                .unwrap()
                .decrypt_message(&ext_proposal.to_bytes().unwrap())
                .await
                .unwrap();

            // decrypt twice ... not ok
            let decryption = alice_central
                .transaction
                .conversation(&id)
                .await
                .unwrap()
                .decrypt_message(&ext_proposal.to_bytes().unwrap())
                .await;
            assert!(matches!(decryption.unwrap_err(), Error::DuplicateMessage));

            // advance alice's epoch
            alice_central
                .transaction
                .conversation(&id)
                .await
                .unwrap()
                .commit_pending_proposals()
                .await
                .unwrap();

            // Epoch has advanced so we cannot detect duplicates anymore
            let decryption = alice_central
                .transaction
                .conversation(&id)
                .await
                .unwrap()
                .decrypt_message(&ext_proposal.to_bytes().unwrap())
                .await;
            assert!(matches!(decryption.unwrap_err(), Error::StaleProposal));
        })
        .await
    }

    // Ensures decrypting an application message is durable (we increment the messages generation & persist the group)
    #[apply(all_cred_cipher)]
    #[wasm_bindgen_test]
    async fn decrypting_duplicate_application_message_should_fail(case: TestContext) {
        let [alice_central, bob_central] = case.sessions().await;
        Box::pin(async move {
            let id = conversation_id();
            alice_central
                .transaction
                .new_conversation(&id, case.credential_type, case.cfg.clone())
                .await
                .unwrap();
            alice_central.invite_all(&case, &id, [&bob_central]).await.unwrap();

            let msg = b"Hello bob";
            let encrypted = alice_central
                .transaction
                .conversation(&id)
                .await
                .unwrap()
                .encrypt_message(msg)
                .await
                .unwrap();

            // decrypt once .. ok
            bob_central
                .transaction
                .conversation(&id)
                .await
                .unwrap()
                .decrypt_message(&encrypted)
                .await
                .unwrap();
            // decrypt twice .. not ok
            let decryption = bob_central
                .transaction
                .conversation(&id)
                .await
                .unwrap()
                .decrypt_message(&encrypted)
                .await;
            assert!(matches!(decryption.unwrap_err(), Error::DuplicateMessage));
        })
        .await
    }
}
