//! This file is intended to fix some issues we have with the Delivery Service. Sometimes, clients
//! receive for the next epoch before receiving the commit for this epoch.
//!
//! Feel free to delete all of this when the issue is fixed on the DS side !

use crate::group_store::GroupStoreValue;
use crate::prelude::decrypt::MlsBufferedConversationDecryptMessage;
use crate::prelude::{
    Client, ConversationId, CryptoError, CryptoResult, MlsCentral, MlsConversation, MlsConversationDecryptMessage,
};
use crate::{CoreCryptoCallbacks, MlsError};
use core_crypto_keystore::entities::{EntityFindParams, MlsPendingMessage};
use mls_crypto_provider::MlsCryptoProvider;
use openmls::prelude::{MlsMessageIn, MlsMessageInBody};
use tls_codec::Deserialize;

impl MlsCentral {
    pub(crate) async fn handle_future_message(
        &mut self,
        id: &ConversationId,
        message: impl AsRef<[u8]>,
    ) -> CryptoResult<MlsConversationDecryptMessage> {
        let keystore = self.mls_backend.borrow_keystore();

        let pending_msg = MlsPendingMessage {
            id: id.clone(),
            message: message.as_ref().to_vec(),
        };
        keystore.save::<MlsPendingMessage>(pending_msg).await?;
        Err(CryptoError::BufferedFutureMessage)
    }

    pub(crate) async fn restore_pending_messages(
        &mut self,
        conversation: &mut MlsConversation,
    ) -> CryptoResult<Option<Vec<MlsBufferedConversationDecryptMessage>>> {
        let parent_conversation = match &conversation.parent_id {
            Some(id) => self.get_conversation(id).await.ok(),
            _ => None,
        };
        let callbacks = self.callbacks.as_ref().map(|boxed| boxed.as_ref());
        conversation
            .restore_pending_messages(
                self.mls_client()?,
                &self.mls_backend,
                callbacks,
                parent_conversation.as_ref(),
            )
            .await
    }
}

impl MlsConversation {
    #[cfg_attr(target_family = "wasm", async_recursion::async_recursion(?Send))]
    #[cfg_attr(not(target_family = "wasm"), async_recursion::async_recursion)]
    pub(crate) async fn restore_pending_messages<'a>(
        &'a mut self,
        client: &'a Client,
        backend: &'a MlsCryptoProvider,
        callbacks: Option<&'a dyn CoreCryptoCallbacks>,
        parent_conversation: Option<&'a GroupStoreValue<Self>>,
    ) -> CryptoResult<Option<Vec<MlsBufferedConversationDecryptMessage>>> {
        let keystore = backend.borrow_keystore();

        let mut pending_messages = keystore
            .find_all::<MlsPendingMessage>(EntityFindParams::default())
            .await?
            .into_iter()
            .filter(|pm| pm.id == self.id.as_slice())
            .try_fold(vec![], |mut acc, m| {
                let msg = MlsMessageIn::tls_deserialize_bytes(m.message.as_slice()).map_err(MlsError::from)?;
                let ct = match msg.body_as_ref() {
                    MlsMessageInBody::PublicMessage(m) => Ok(m.content_type()),
                    MlsMessageInBody::PrivateMessage(m) => Ok(m.content_type()),
                    _ => Err(CryptoError::ImplementationError),
                }?;
                acc.push((ct as u8, msg));
                CryptoResult::Ok(acc)
            })?;

        // We want to restore application messages first, then Proposals & finally Commits
        // luckily for us that's the exact same order as the [ContentType] enum
        pending_messages.sort_by(|(a, _), (b, _)| a.cmp(b));

        let mut decrypted_messages = Vec::with_capacity(pending_messages.len());
        for (_, m) in pending_messages {
            let parent_conversation = match &self.parent_id {
                Some(_) => Some(parent_conversation.ok_or(CryptoError::ParentGroupNotFound)?),
                _ => None,
            };
            let restore_pending = false; // to prevent infinite recursion
            let decrypted = self
                .decrypt_message(m, parent_conversation, client, backend, callbacks, restore_pending)
                .await?;
            decrypted_messages.push(decrypted.into());
        }

        let decrypted_messages = (!decrypted_messages.is_empty()).then_some(decrypted_messages);

        Ok(decrypted_messages)
    }
}

#[cfg(test)]
pub mod tests {
    use crate::{test_utils::*, CryptoError};
    use wasm_bindgen_test::*;

    wasm_bindgen_test_configure!(run_in_browser);

    #[apply(all_cred_cipher)]
    #[wasm_bindgen_test]
    pub async fn should_buffer_and_reapply_messages_after_commit_merged_for_sender(case: TestCase) {
        run_test_with_client_ids(
            case.clone(),
            ["alice", "bob", "charlie", "debbie"],
            move |[mut alice_central, mut bob_central, mut charlie_central, mut debbie_central]| {
                Box::pin(async move {
                    let id = conversation_id();
                    alice_central
                        .new_conversation(id.clone(), case.credential_type, case.cfg.clone())
                        .await
                        .unwrap();
                    alice_central.invite_all(&case, &id, [&mut bob_central]).await.unwrap();

                    // Bob creates a commit but won't merge it immediately
                    let unmerged_commit = bob_central.update_keying_material(&id).await.unwrap();

                    // Alice decrypts the commit...
                    alice_central
                        .decrypt_message(&id, unmerged_commit.commit.to_bytes().unwrap())
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

                    // And now Bob will have to decrypt those messages while he hasn't yet merged its commit
                    // To add more fun, he will buffer the messages in exactly the wrong order (to make
                    // sure he reapplies them in the right order afterwards)
                    let messages = vec![commit.commit, external_proposal, proposal]
                        .into_iter()
                        .map(|m| m.to_bytes().unwrap());
                    for m in messages {
                        let decrypt = bob_central.decrypt_message(&id, m).await;
                        assert!(matches!(decrypt.unwrap_err(), CryptoError::BufferedFutureMessage));
                    }
                    let decrypt = bob_central.decrypt_message(&id, app_msg).await;
                    assert!(matches!(decrypt.unwrap_err(), CryptoError::BufferedFutureMessage));

                    // Bob should have buffered the messages
                    assert_eq!(bob_central.count_entities().await.pending_messages, 4);

                    // Finally, Bob receives the green light from the DS and he can merge the external commit
                    let Some(restored_messages) = bob_central.commit_accepted(&id).await.unwrap() else {
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

    #[apply(all_cred_cipher)]
    #[wasm_bindgen_test]
    pub async fn should_buffer_and_reapply_messages_after_commit_merged_for_receivers(case: TestCase) {
        run_test_with_client_ids(
            case.clone(),
            ["alice", "bob", "charlie", "debbie"],
            move |[mut alice_central, mut bob_central, mut charlie_central, mut debbie_central]| {
                Box::pin(async move {
                    let id = conversation_id();
                    alice_central
                        .new_conversation(id.clone(), case.credential_type, case.cfg.clone())
                        .await
                        .unwrap();

                    // Bob joins the group with an external commit...
                    let gi = alice_central.get_group_info(&id).await;
                    let ext_commit = bob_central
                        .join_by_external_commit(gi, case.custom_cfg(), case.credential_type)
                        .await
                        .unwrap();
                    bob_central.merge_pending_group_from_external_commit(&id).await.unwrap();

                    // And before others had the chance to get the commit, Bob will create & send messages in the next epoch
                    // which Alice will have to buffer until she receives the commit.
                    // This simulates what the DS does with unordered messages
                    let epoch = bob_central.conversation_epoch(&id).await.unwrap();
                    let external_proposal = charlie_central
                        .new_external_add_proposal(id.clone(), epoch.into(), case.ciphersuite(), case.credential_type)
                        .await
                        .unwrap();
                    let app_msg = bob_central.encrypt_message(&id, b"Hello Alice !").await.unwrap();
                    let proposal = bob_central.new_update_proposal(&id).await.unwrap().proposal;
                    bob_central
                        .decrypt_message(&id, external_proposal.to_bytes().unwrap())
                        .await
                        .unwrap();
                    let debbie = debbie_central.rand_member(&case).await;
                    let commit = bob_central
                        .add_members_to_conversation(&id, &mut [debbie])
                        .await
                        .unwrap();
                    bob_central.commit_accepted(&id).await.unwrap();
                    charlie_central
                        .process_welcome_message(commit.welcome.clone().into(), case.custom_cfg())
                        .await
                        .unwrap();
                    debbie_central
                        .process_welcome_message(commit.welcome.clone().into(), case.custom_cfg())
                        .await
                        .unwrap();

                    // And now Alice will have to decrypt those messages while he hasn't yet merged the commit
                    // To add more fun, he will buffer the messages in exactly the wrong order (to make
                    // sure he reapplies them in the right order afterwards)
                    let messages = vec![commit.commit, external_proposal, proposal]
                        .into_iter()
                        .map(|m| m.to_bytes().unwrap());
                    for m in messages {
                        let decrypt = alice_central.decrypt_message(&id, m).await;
                        assert!(matches!(decrypt.unwrap_err(), CryptoError::BufferedFutureMessage));
                    }
                    let decrypt = alice_central.decrypt_message(&id, app_msg).await;
                    assert!(matches!(decrypt.unwrap_err(), CryptoError::BufferedFutureMessage));

                    // Alice should have buffered the messages
                    assert_eq!(alice_central.count_entities().await.pending_messages, 4);

                    // Finally, Alice receives the original commit for this epoch
                    let original_commit = ext_commit.commit.to_bytes().unwrap();

                    let Some(restored_messages) = alice_central
                        .decrypt_message(&id, original_commit)
                        .await
                        .unwrap()
                        .buffered_messages
                    else {
                        panic!("Bob's messages should have been restored at this point");
                    };
                    for (i, m) in restored_messages.into_iter().enumerate() {
                        match i {
                            0 => {
                                // this is the application message
                                assert_eq!(&m.app_msg.unwrap(), b"Hello Alice !");
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
                    assert!(alice_central.try_talk_to(&id, &mut bob_central).await.is_ok());
                    // because Alice's commit got merged
                    assert!(alice_central.try_talk_to(&id, &mut charlie_central).await.is_ok());
                    // because Debbie's external proposal got merged through the commit
                    assert!(alice_central.try_talk_to(&id, &mut debbie_central).await.is_ok());

                    // After merging we should erase all those pending messages
                    assert_eq!(alice_central.count_entities().await.pending_messages, 0);
                })
            },
        )
        .await
    }
}
