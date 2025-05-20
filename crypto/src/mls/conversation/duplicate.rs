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
    use crate::test_utils::*;
    use wasm_bindgen_test::*;

    wasm_bindgen_test_configure!(run_in_browser);

    #[apply(all_cred_cipher)]
    #[wasm_bindgen_test]
    async fn decrypting_duplicate_member_commit_should_fail(case: TestContext) {
        // cannot work in pure ciphertext since we'd have to decrypt the message first
        if case.is_pure_ciphertext() {
            return;
        }

        let [alice, bob] = case.sessions().await;
        Box::pin(async move {
            let conversation = case.create_conversation([&alice, &bob]).await;

            // an commit to verify that we can still detect wrong epoch correctly
            let commit_guard = conversation.unmerged_commit().await;
            let unknown_commit = commit_guard.message();
            let conversation = commit_guard.finish();
            conversation.guard().await.clear_pending_commit().await.unwrap();

            let commit_guard = conversation.update_guarded().await;
            let commit = commit_guard.message();

            // decrypt once ... ok
            let conversation = commit_guard.notify_members().await;
            // decrypt twice ... not ok
            let decrypt_duplicate = conversation
                .guard_of(&bob)
                .await
                .decrypt_message(&commit.to_bytes().unwrap())
                .await;
            assert!(matches!(decrypt_duplicate.unwrap_err(), Error::DuplicateMessage));

            // Decrypting unknown commit.
            // It fails with this error since it's not the commit who has created this epoch
            let decrypt_lost_commit = conversation
                .guard_of(&bob)
                .await
                .decrypt_message(&unknown_commit.to_bytes().unwrap())
                .await;
            assert!(matches!(decrypt_lost_commit.unwrap_err(), Error::StaleCommit));
        })
        .await
    }

    #[apply(all_cred_cipher)]
    #[wasm_bindgen_test]
    async fn decrypting_duplicate_external_commit_should_fail(case: TestContext) {
        let [alice, bob] = case.sessions().await;
        Box::pin(async move {
            let conversation = case.create_conversation([&alice]).await;

            // an external commit to verify that we can still detect wrong epoch correctly
            let (commit_guard, mut pending_conversation) = conversation.unmerged_external_join_guarded(&bob).await;
            let unknown_ext_commit = commit_guard.message();
            pending_conversation.clear().await.unwrap();
            let conversation = commit_guard.finish();

            let commit_guard = conversation.external_join_guarded(&bob).await;
            let ext_commit = commit_guard.message();

            // decrypt once ... ok
            let conversation = commit_guard.notify_members().await;
            // decrypt twice ... not ok
            let decryption = conversation
                .guard()
                .await
                .decrypt_message(&ext_commit.to_bytes().unwrap())
                .await;
            assert!(matches!(decryption.unwrap_err(), Error::DuplicateMessage));

            // Decrypting unknown external commit.
            // It fails with this error since it's not the external commit who has created this epoch
            let decryption = conversation
                .guard()
                .await
                .decrypt_message(&unknown_ext_commit.to_bytes().unwrap())
                .await;
            assert!(matches!(decryption.unwrap_err(), Error::StaleCommit));
        })
        .await
    }

    #[apply(all_cred_cipher)]
    #[wasm_bindgen_test]
    async fn decrypting_duplicate_proposal_should_fail(case: TestContext) {
        let [alice, bob] = case.sessions().await;
        Box::pin(async move {
            let conversation = case.create_conversation([&alice, &bob]).await;

            let proposal_guard = conversation.update_proposal_guarded().await;
            let proposal = proposal_guard.message();

            // decrypt once ... ok
            let conversation = proposal_guard.notify_members().await;

            // decrypt twice ... not ok
            let decryption = conversation
                .guard_of(&bob)
                .await
                .decrypt_message(&proposal.to_bytes().unwrap())
                .await;
            assert!(matches!(decryption.unwrap_err(), Error::DuplicateMessage));

            // advance Bob's epoch to trigger failure
            let conversation = conversation.acting_as(&bob).await.commit_pending_proposals().await;

            // Epoch has advanced so we cannot detect duplicates anymore
            let decryption = conversation
                .guard_of(&bob)
                .await
                .decrypt_message(&proposal.to_bytes().unwrap())
                .await;
            assert!(matches!(decryption.unwrap_err(), Error::StaleProposal));
        })
        .await
    }

    #[apply(all_cred_cipher)]
    #[wasm_bindgen_test]
    async fn decrypting_duplicate_external_proposal_should_fail(case: TestContext) {
        let [alice, bob] = case.sessions().await;
        Box::pin(async move {
            let conversation = case.create_conversation([&alice]).await;

            let proposal_guard = conversation.external_join_proposal_guarded(&bob).await;
            let proposal = proposal_guard.message();

            // decrypt once ... ok
            let conversation = proposal_guard.notify_members().await;

            // decrypt twice ... not ok
            let decryption = conversation
                .guard()
                .await
                .decrypt_message(&proposal.to_bytes().unwrap())
                .await;
            assert!(matches!(decryption.unwrap_err(), Error::DuplicateMessage));

            // advance alice's epoch
            let conversation = conversation.commit_pending_proposals().await;

            // Epoch has advanced so we cannot detect duplicates anymore
            let decryption = conversation
                .guard()
                .await
                .decrypt_message(&proposal.to_bytes().unwrap())
                .await;
            assert!(matches!(decryption.unwrap_err(), Error::StaleProposal));
        })
        .await
    }

    // Ensures decrypting an application message is durable (we increment the messages generation & persist the group)
    #[apply(all_cred_cipher)]
    #[wasm_bindgen_test]
    async fn decrypting_duplicate_application_message_should_fail(case: TestContext) {
        let [alice, bob] = case.sessions().await;
        Box::pin(async move {
            let conversation = case.create_conversation([&alice, &bob]).await;

            let msg = b"Hello bob";
            let encrypted = conversation.guard().await.encrypt_message(msg).await.unwrap();

            // decrypt once .. ok
            conversation
                .guard_of(&bob)
                .await
                .decrypt_message(&encrypted)
                .await
                .unwrap();
            // decrypt twice .. not ok
            let decryption = conversation.guard_of(&bob).await.decrypt_message(&encrypted).await;
            assert!(matches!(decryption.unwrap_err(), Error::DuplicateMessage));
        })
        .await
    }
}
