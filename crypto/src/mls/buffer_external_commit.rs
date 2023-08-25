//! This file is intended to fix some issues we have with the Delivery Service. When a client joins
//! a group via an external commit, it sometimes receives messages (most of the time renewed external
//! proposals) for the new epoch whereas it does not yet have the confirmation from the DS that his
//! external has been accepted. Hence it is not merged locally and it cannot decrypt any message.
//!
//! Feel free to delete all of this when the issue is fixed on the DS side !

use crate::prelude::{ConversationId, CryptoError, CryptoResult, MlsCentral, MlsConversationDecryptMessage};
use core_crypto_keystore::entities::{MlsPendingMessage, PersistedMlsPendingGroup};

impl MlsCentral {
    pub(crate) async fn handle_when_group_is_pending(
        &mut self,
        id: &ConversationId,
        message: impl AsRef<[u8]>,
    ) -> CryptoResult<MlsConversationDecryptMessage> {
        let keystore = self.mls_backend.borrow_keystore();
        let Ok(Some(pending_group)) = keystore.find::<PersistedMlsPendingGroup>(id).await else {
            return Err(CryptoError::ConversationNotFound(id.clone()));
        };

        let pending_msg = MlsPendingMessage {
            id: pending_group.id.clone(),
            message: message.as_ref().to_vec(),
        };
        keystore.save::<MlsPendingMessage>(pending_msg).await?;
        Err(CryptoError::UnmergedPendingGroup)
    }
}

#[cfg(test)]
pub mod tests {
    use crate::{test_utils::*, CryptoError};
    use wasm_bindgen_test::*;

    wasm_bindgen_test_configure!(run_in_browser);

    #[apply(all_cred_cipher)]
    #[wasm_bindgen_test]
    pub async fn should_buffer_and_reapply_messages_after_external_commit_merged(case: TestCase) {
        run_test_with_client_ids(
            case.clone(),
            ["alice", "bob", "charlie", "debbie"],
            move |[mut alice_central, mut bob_central, mut charlie_central, mut debbie_central]| {
                Box::pin(async move {
                    let id = conversation_id();
                    alice_central
                        .new_conversation(&id, case.credential_type, case.cfg.clone())
                        .await
                        .unwrap();

                    // Bob tries to join Alice's group with an external commit
                    let gi = alice_central.get_group_info(&id).await;
                    let external_commit = bob_central
                        .join_by_external_commit(gi, case.custom_cfg(), case.credential_type)
                        .await
                        .unwrap();

                    // Alice decrypts the external commit...
                    alice_central
                        .decrypt_message(&id, external_commit.commit.to_bytes().unwrap())
                        .await
                        .unwrap();

                    // Meanwhile Debbie joins the party by creating an external proposal
                    let epoch = alice_central.conversation_epoch(&id).await.unwrap();
                    let external_proposal = debbie_central
                        .new_external_add_proposal(id.clone(), epoch.into(), case.ciphersuite(), case.credential_type)
                        .await
                        .unwrap();

                    // ...then Alice generates new messages for this epoch
                    let app_msg = alice_central.encrypt_message(&id, b"Hello Bob !").await.unwrap();
                    let proposal = alice_central.new_update_proposal(&id).await.unwrap().proposal;
                    alice_central
                        .decrypt_message(&id, external_proposal.to_bytes().unwrap())
                        .await
                        .unwrap();
                    let charlie = charlie_central.rand_member(&case).await;
                    let commit = alice_central
                        .add_members_to_conversation(&id, &mut [charlie])
                        .await
                        .unwrap();
                    alice_central.commit_accepted(&id).await.unwrap();
                    charlie_central
                        .process_welcome_message(commit.welcome.clone().into(), case.custom_cfg())
                        .await
                        .unwrap();
                    debbie_central
                        .process_welcome_message(commit.welcome.clone().into(), case.custom_cfg())
                        .await
                        .unwrap();

                    // And now Bob will have to decrypt those messages while he hasn't yet merged its external commit
                    // To add more fun, he will buffer the messages in exactly the wrong order (to make
                    // sure he reapplies them in the right order afterwards)
                    let messages = vec![commit.commit, external_proposal, proposal]
                        .into_iter()
                        .map(|m| m.to_bytes().unwrap());
                    for m in messages {
                        let decrypt = bob_central.decrypt_message(&id, m).await;
                        assert!(matches!(decrypt.unwrap_err(), CryptoError::UnmergedPendingGroup));
                    }
                    let decrypt = bob_central.decrypt_message(&id, app_msg).await;
                    assert!(matches!(decrypt.unwrap_err(), CryptoError::UnmergedPendingGroup));

                    // Bob should have buffered the messages
                    assert_eq!(bob_central.count_entities().await.pending_messages, 4);

                    // Finally, Bob receives the green light from the DS and he can merge the external commit
                    let Some(restored_messages) =
                        bob_central.merge_pending_group_from_external_commit(&id).await.unwrap()
                    else {
                        panic!("Alice's messages should have been restored at this point");
                    };
                    for (i, m) in restored_messages.into_iter().enumerate() {
                        match i {
                            0 => {
                                // this is the application message
                                assert_eq!(&m.app_msg.unwrap(), b"Hello Bob !");
                                assert!(!m.has_epoch_changed);
                            }
                            1 | 2 => {
                                // this is either the member or the external proposal
                                assert!(m.app_msg.is_none());
                                assert!(!m.has_epoch_changed);
                            }
                            3 => {
                                // this is the commit
                                assert!(m.app_msg.is_none());
                                assert!(m.has_epoch_changed);
                            }
                            _ => unreachable!(),
                        }
                    }
                    // because external commit got merged
                    assert!(bob_central.try_talk_to(&id, &mut alice_central).await.is_ok());
                    // because Alice's commit got merged
                    assert!(bob_central.try_talk_to(&id, &mut charlie_central).await.is_ok());
                    // because Debbie's external proposal got merged through the commit
                    assert!(bob_central.try_talk_to(&id, &mut debbie_central).await.is_ok());

                    // After merging we should erase all those pending messages
                    assert_eq!(bob_central.count_entities().await.pending_messages, 0);
                })
            },
        )
        .await
    }
}
