//! This file is intended to fix some issues we have with the Delivery Service. Sometimes, clients
//! receive for the next epoch before receiving the commit for this epoch.
//!
//! Feel free to delete all of this when the issue is fixed on the DS side !

use super::{ConversationGuard, Error, Result};
use crate::obfuscate::Obfuscated;
use crate::{
    KeystoreError, RecursiveError,
    context::CentralContext,
    prelude::{Client, ConversationId, MlsConversation, decrypt::MlsBufferedConversationDecryptMessage},
};
use core_crypto_keystore::{
    connection::FetchFromDatabase,
    entities::{EntityFindParams, MlsPendingMessage},
};
use log::{error, info, trace};
use mls_crypto_provider::MlsCryptoProvider;
use openmls::prelude::{MlsMessageIn, MlsMessageInBody};
use tls_codec::Deserialize;

impl CentralContext {
    pub(crate) async fn handle_future_message(&self, id: &ConversationId, message: impl AsRef<[u8]>) -> Result<()> {
        let keystore = self
            .keystore()
            .await
            .map_err(RecursiveError::root("getting keystore"))?;

        let pending_msg = MlsPendingMessage {
            foreign_id: id.clone(),
            message: message.as_ref().to_vec(),
        };
        keystore
            .save::<MlsPendingMessage>(pending_msg)
            .await
            .map_err(KeystoreError::wrap("saving pending mls message"))?;
        Ok(())
    }

    pub(crate) async fn restore_pending_messages(
        &self,
        conversation: &mut MlsConversation,
        is_rejoin: bool,
    ) -> Result<Option<Vec<MlsBufferedConversationDecryptMessage>>> {
        let parent_conversation = match &conversation.parent_id {
            Some(id) => self.conversation_guard(id).await.ok(),
            _ => None,
        };
        let client = &self
            .mls_client()
            .await
            .map_err(RecursiveError::root("getting mls client"))?;
        let mls_provider = self
            .mls_provider()
            .await
            .map_err(RecursiveError::root("getting mls provider"))?;
        conversation
            .restore_pending_messages(client, &mls_provider, parent_conversation.as_ref(), is_rejoin)
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
        parent_conversation: Option<&'a ConversationGuard>,
        is_rejoin: bool,
    ) -> Result<Option<Vec<MlsBufferedConversationDecryptMessage>>> {
        // using the macro produces a clippy warning
        let result = async move {
            let keystore = backend.keystore();
            let group_id = self.id().as_slice();
            if is_rejoin {
                // This means the external commit is about rejoining the group.
                // This is most of the time a last resort measure (for example when a commit is dropped)
                // and you go out of sync so there's no point in decrypting buffered messages

                trace!("External commit trying to rejoin group");
                if keystore
                    .find::<MlsPendingMessage>(group_id)
                    .await
                    .map_err(KeystoreError::wrap("finding mls pending message by group id"))?
                    .is_some()
                {
                    keystore
                        .remove::<MlsPendingMessage, _>(group_id)
                        .await
                        .map_err(KeystoreError::wrap("removing mls pending message"))?;
                }
                return Ok(None);
            }

            let mut pending_messages = keystore
                .find_all::<MlsPendingMessage>(EntityFindParams::default())
                .await
                .map_err(KeystoreError::wrap("finding all mls pending messages"))?
                .into_iter()
                .filter(|pm| pm.foreign_id == group_id)
                .map(|m| -> Result<_> {
                    let msg = MlsMessageIn::tls_deserialize(&mut m.message.as_slice())
                        .map_err(Error::tls_deserialize("mls message in"))?;
                    let ct = match msg.body_as_ref() {
                        MlsMessageInBody::PublicMessage(m) => m.content_type(),
                        MlsMessageInBody::PrivateMessage(m) => m.content_type(),
                        _ => return Err(Error::InappropriateMessageBodyType),
                    };
                    Ok((ct as u8, msg))
                })
                .collect::<Result<Vec<_>>>()?;

            // We want to restore application messages first, then Proposals & finally Commits
            // luckily for us that's the exact same order as the [ContentType] enum
            pending_messages.sort_by(|(a, _), (b, _)| a.cmp(b));

            info!(group_id = Obfuscated::from(&self.id); "Attempting to restore {} buffered messages", pending_messages.len());

            let mut decrypted_messages = Vec::with_capacity(pending_messages.len());
            for (_, m) in pending_messages {
                let parent_conversation = match &self.parent_id {
                    Some(_) => Some(parent_conversation.ok_or(Error::ParentGroupNotFound)?),
                    _ => None,
                };
                let restore_pending = false; // to prevent infinite recursion
                let decrypted = self
                    .decrypt_message(m, parent_conversation, client, backend, restore_pending)
                    .await?;
                decrypted_messages.push(decrypted.into());
            }

            let decrypted_messages = (!decrypted_messages.is_empty()).then_some(decrypted_messages);

            Ok(decrypted_messages)
        }
        .await;
        if let Err(e) = &result {
            error!(error:% = e; "Error restoring pending messages");
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::super::error::Error;
    use crate::mls::conversation::Conversation as _;
    use crate::prelude::MlsConversationDecryptMessage;
    use crate::test_utils::*;
    use wasm_bindgen_test::*;

    wasm_bindgen_test_configure!(run_in_browser);

    #[apply(all_cred_cipher)]
    #[wasm_bindgen_test]
    async fn should_buffer_and_reapply_messages_after_commit_merged_for_sender(case: TestCase) {
        if case.is_pure_ciphertext() {
            // The use case tested here requires inspecting your own commit.
            // Openmls does not support this currently when protocol messages are encrypted.
            return;
        }
        run_test_with_client_ids(
            case.clone(),
            ["alice", "bob", "charlie", "debbie"],
            move |[alice_central, bob_central, charlie_central, debbie_central]| {
                Box::pin(async move {
                    let id = conversation_id();
                    alice_central
                        .context
                        .new_conversation(&id, case.credential_type, case.cfg.clone())
                        .await
                        .unwrap();
                    alice_central.invite_all(&case, &id, [&bob_central]).await.unwrap();

                    // Bob creates a commit but won't merge it immediately (e.g, because his app crashes before he receives the success response from the ds)
                    let unmerged_commit = bob_central.create_unmerged_commit(&id).await;

                    // Alice decrypts the commit...
                    alice_central
                        .context
                        .conversation_guard(&id)
                        .await
                        .unwrap()
                        .decrypt_message(unmerged_commit.commit.to_bytes().unwrap())
                        .await
                        .unwrap();

                    // Meanwhile Debbie joins the party by creating an external proposal
                    let epoch = alice_central
                        .context
                        .conversation_guard(&id)
                        .await
                        .unwrap()
                        .epoch()
                        .await;
                    let external_proposal = debbie_central
                        .context
                        .new_external_add_proposal(id.clone(), epoch.into(), case.ciphersuite(), case.credential_type)
                        .await
                        .unwrap();

                    // ...then Alice generates new messages for this epoch
                    let app_msg = alice_central
                        .context
                        .conversation_guard(&id)
                        .await
                        .unwrap()
                        .encrypt_message(b"Hello Bob !")
                        .await
                        .unwrap();
                    let proposal = alice_central.context.new_update_proposal(&id).await.unwrap().proposal;
                    alice_central
                        .context
                        .conversation_guard(&id)
                        .await
                        .unwrap()
                        .decrypt_message(external_proposal.to_bytes().unwrap())
                        .await
                        .unwrap();
                    let charlie = charlie_central.rand_key_package(&case).await;
                    alice_central
                        .context
                        .conversation_guard(&id)
                        .await
                        .unwrap()
                        .add_members(vec![charlie])
                        .await
                        .unwrap();
                    let commit = alice_central.mls_transport.latest_commit_bundle().await;
                    charlie_central
                        .context
                        .process_welcome_message(commit.welcome.clone().unwrap().into(), case.custom_cfg())
                        .await
                        .unwrap();
                    debbie_central
                        .context
                        .process_welcome_message(commit.welcome.clone().unwrap().into(), case.custom_cfg())
                        .await
                        .unwrap();

                    // And now Bob will have to decrypt those messages while he hasn't yet merged its commit
                    // To add more fun, he will buffer the messages in exactly the wrong order (to make
                    // sure he reapplies them in the right order afterwards)
                    let messages = vec![commit.commit, external_proposal, proposal]
                        .into_iter()
                        .map(|m| m.to_bytes().unwrap());
                    for m in messages {
                        let decrypt = bob_central
                            .context
                            .conversation_guard(&id)
                            .await
                            .unwrap()
                            .decrypt_message(m)
                            .await;
                        assert!(matches!(decrypt.unwrap_err(), Error::BufferedFutureMessage { .. }));
                    }
                    let decrypt = bob_central
                        .context
                        .conversation_guard(&id)
                        .await
                        .unwrap()
                        .decrypt_message(app_msg)
                        .await;
                    assert!(matches!(decrypt.unwrap_err(), Error::BufferedFutureMessage { .. }));

                    // Bob should have buffered the messages
                    assert_eq!(bob_central.context.count_entities().await.pending_messages, 4);

                    // Finally, Bob receives the green light from the DS and he can merge the external commit
                    let MlsConversationDecryptMessage {
                        buffered_messages: Some(restored_messages),
                        ..
                    } = bob_central
                        .context
                        .conversation_guard(&id)
                        .await
                        .unwrap()
                        .decrypt_message(unmerged_commit.commit.to_bytes().unwrap())
                        .await
                        .unwrap()
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
                    assert!(bob_central.try_talk_to(&id, &alice_central).await.is_ok());
                    // because Alice's commit got merged
                    assert!(bob_central.try_talk_to(&id, &charlie_central).await.is_ok());
                    // because Debbie's external proposal got merged through the commit
                    assert!(bob_central.try_talk_to(&id, &debbie_central).await.is_ok());

                    // After merging we should erase all those pending messages
                    assert_eq!(bob_central.context.count_entities().await.pending_messages, 0);
                })
            },
        )
        .await
    }

    #[apply(all_cred_cipher)]
    #[wasm_bindgen_test]
    async fn should_buffer_and_reapply_messages_after_commit_merged_for_receivers(case: TestCase) {
        if case.is_pure_ciphertext() {
            // The use case tested here requires inspecting your own commit.
            // Openmls does not support this currently when protocol messages are encrypted.
            return;
        }
        run_test_with_client_ids(
            case.clone(),
            ["alice", "bob", "charlie", "debbie"],
            move |[alice_central, bob_central, charlie_central, debbie_central]| {
                Box::pin(async move {
                    let id = conversation_id();
                    alice_central
                        .context
                        .new_conversation(&id, case.credential_type, case.cfg.clone())
                        .await
                        .unwrap();

                    // Bob joins the group with an external commit...
                    let gi = alice_central.get_group_info(&id).await;
                    bob_central
                        .context
                        .join_by_external_commit(gi, case.custom_cfg(), case.credential_type)
                        .await
                        .unwrap();

                    let ext_commit = bob_central.mls_transport.latest_commit_bundle().await;

                    // And before others had the chance to get the commit, Bob will create & send messages in the next epoch
                    // which Alice will have to buffer until she receives the commit.
                    // This simulates what the DS does with unordered messages
                    let epoch = bob_central.context.conversation_guard(&id).await.unwrap().epoch().await;
                    let external_proposal = charlie_central
                        .context
                        .new_external_add_proposal(id.clone(), epoch.into(), case.ciphersuite(), case.credential_type)
                        .await
                        .unwrap();
                    let app_msg = bob_central
                        .context
                        .conversation_guard(&id)
                        .await
                        .unwrap()
                        .encrypt_message(b"Hello Alice !")
                        .await
                        .unwrap();
                    let proposal = bob_central.context.new_update_proposal(&id).await.unwrap().proposal;
                    bob_central
                        .context
                        .conversation_guard(&id)
                        .await
                        .unwrap()
                        .decrypt_message(external_proposal.to_bytes().unwrap())
                        .await
                        .unwrap();
                    let debbie = debbie_central.rand_key_package(&case).await;
                    bob_central
                        .context
                        .conversation_guard(&id)
                        .await
                        .unwrap()
                        .add_members(vec![debbie])
                        .await
                        .unwrap();
                    let commit = bob_central.mls_transport.latest_commit_bundle().await;
                    charlie_central
                        .context
                        .process_welcome_message(commit.welcome.clone().unwrap().into(), case.custom_cfg())
                        .await
                        .unwrap();
                    debbie_central
                        .context
                        .process_welcome_message(commit.welcome.clone().unwrap().into(), case.custom_cfg())
                        .await
                        .unwrap();

                    // And now Alice will have to decrypt those messages while he hasn't yet merged the commit
                    // To add more fun, he will buffer the messages in exactly the wrong order (to make
                    // sure he reapplies them in the right order afterwards)
                    let messages = vec![commit.commit, external_proposal, proposal]
                        .into_iter()
                        .map(|m| m.to_bytes().unwrap());
                    for m in messages {
                        let decrypt = alice_central
                            .context
                            .conversation_guard(&id)
                            .await
                            .unwrap()
                            .decrypt_message(m)
                            .await;
                        assert!(matches!(decrypt.unwrap_err(), Error::BufferedFutureMessage { .. }));
                    }
                    let decrypt = alice_central
                        .context
                        .conversation_guard(&id)
                        .await
                        .unwrap()
                        .decrypt_message(app_msg)
                        .await;
                    assert!(matches!(decrypt.unwrap_err(), Error::BufferedFutureMessage { .. }));

                    // Alice should have buffered the messages
                    assert_eq!(alice_central.context.count_entities().await.pending_messages, 4);

                    // Finally, Alice receives the original commit for this epoch
                    let original_commit = ext_commit.commit.to_bytes().unwrap();

                    let Some(restored_messages) = alice_central
                        .context
                        .conversation_guard(&id)
                        .await
                        .unwrap()
                        .decrypt_message(original_commit)
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
                    assert!(alice_central.try_talk_to(&id, &bob_central).await.is_ok());
                    // because Alice's commit got merged
                    assert!(alice_central.try_talk_to(&id, &charlie_central).await.is_ok());
                    // because Debbie's external proposal got merged through the commit
                    assert!(alice_central.try_talk_to(&id, &debbie_central).await.is_ok());

                    // After merging we should erase all those pending messages
                    assert_eq!(alice_central.context.count_entities().await.pending_messages, 0);
                })
            },
        )
        .await
    }

    /// Replicating [WPB-15810]
    ///
    /// [WPB-15810]: https://wearezeta.atlassian.net/browse/WPB-15810
    #[apply(all_cred_cipher)]
    async fn wpb_15810(case: TestCase) {
        use openmls::{
            group::GroupId,
            prelude::{ExternalProposal, SenderExtensionIndex},
        };

        use crate::mls;

        if case.is_pure_ciphertext() {
            // The use case tested here requires inspecting your own commit.
            // Openmls does not support this currently when protocol messages are encrypted.
            return;
        }
        run_test_with_client_ids(
            case.clone(),
            ["external_0", "new_member", "member_27", "observer", "114", "115"],
            move |[external_0, new_member, member_27, observer, member_114, member_115]| {
                Box::pin(async move {
                    // scenario start: everyone except "new_member" is in the conversation
                    let conv_id = conversation_id();

                    // set up external_0 as the backend / delivery service
                    let signature_key = external_0.client_signature_key(&case).await.as_slice().to_vec();
                    let mut config = case.cfg.clone();
                    observer
                        .context
                        .set_raw_external_senders(&mut config, vec![signature_key])
                        .await
                        .unwrap();

                    // create and initialize the conversation
                    observer
                        .context
                        .new_conversation(&conv_id, case.credential_type, config)
                        .await
                        .unwrap();

                    // everyone else except new_member joins (also except observer, who created it)
                    observer
                        .invite_all(&case, &conv_id, [&member_114, &member_115, &member_27])
                        .await
                        .unwrap();

                    // Everyone should agree on the overall state here, to wit: the group consists of everyone
                    // except "new_member", and "external_0", and no messages have been sent.
                    // At this point only the observer is going to receive messages, because that shouldn't impact group state.

                    // external 0 sends a proposal to remove 114
                    let leaf_of_114 = observer.index_of(&conv_id, member_114.get_client_id().await).await;
                    let sender_index = SenderExtensionIndex::new(0);
                    let sc = case.signature_scheme();
                    let ct = case.credential_type;
                    let cb = external_0.find_most_recent_credential_bundle(sc, ct).await.unwrap();
                    let group_id = GroupId::from_slice(&conv_id[..]);
                    let epoch = observer.get_conversation_unchecked(&conv_id).await.group.epoch();
                    let proposal_remove_114_1 = ExternalProposal::new_remove(
                        leaf_of_114,
                        group_id.clone(),
                        epoch,
                        &cb.signature_key,
                        sender_index,
                    )
                    .unwrap();

                    // now bump the epoch in external_0: the new member has joined
                    let (new_member_join_commit, mut pending_conversation) = new_member
                        .create_unmerged_external_commit(
                            observer.get_group_info(&conv_id).await,
                            case.custom_cfg(),
                            case.credential_type,
                        )
                        .await;

                    let new_member_join_commit = new_member_join_commit.commit;

                    pending_conversation.merge().await.unwrap();

                    // also create the same proposal with the epoch increased by 1
                    let leaf_of_114 = new_member.index_of(&conv_id, member_114.get_client_id().await).await;
                    let proposal_remove_114_2 = ExternalProposal::new_remove(
                        leaf_of_114,
                        group_id.clone(),
                        (epoch.as_u64() + 1).into(),
                        &cb.signature_key,
                        sender_index,
                    )
                    .unwrap();

                    // now our observer receives these messages out of order
                    println!("observer executing first proposal");
                    observer
                        .context
                        .conversation_guard(&conv_id)
                        .await
                        .unwrap()
                        .decrypt_message(&proposal_remove_114_1.to_bytes().unwrap())
                        .await
                        .unwrap();
                    println!("observer executing second proposal");
                    let result = observer
                        .context
                        .conversation_guard(&conv_id)
                        .await
                        .unwrap()
                        .decrypt_message(&proposal_remove_114_2.to_bytes().unwrap())
                        .await;
                    assert!(matches!(
                        result.unwrap_err(),
                        Error::BufferedFutureMessage { message_epoch: 2 }
                    ));
                    println!("executing commit adding new user");
                    observer
                        .context
                        .conversation_guard(&conv_id)
                        .await
                        .unwrap()
                        .decrypt_message(&new_member_join_commit.to_bytes().unwrap())
                        .await
                        .unwrap();

                    // now the new member receives the messages in order
                    println!("new_member executing first proposal");
                    assert!(matches!(
                        new_member
                            .context
                            .conversation_guard(&conv_id)
                            .await
                            .unwrap()
                            .decrypt_message(&proposal_remove_114_1.to_bytes().unwrap())
                            .await
                            .unwrap_err(),
                        mls::conversation::Error::StaleProposal,
                    ));
                    println!("new_member executing second proposal");
                    new_member
                        .context
                        .conversation_guard(&conv_id)
                        .await
                        .unwrap()
                        .decrypt_message(&proposal_remove_114_2.to_bytes().unwrap())
                        .await
                        .unwrap();

                    // now let's switch to the perspective of member 27
                    // they have observed exactly one of the "remove 114" proposals,
                    // plus a "remove 115" proposal. We can assume that they observe the 2nd
                    // "remove 114" proposal because they advanced the epoch correctly when
                    // the new member was added.
                    let leaf_of_115 = observer.index_of(&conv_id, member_115.get_client_id().await).await;
                    let epoch = observer.get_conversation_unchecked(&conv_id).await.group.epoch();
                    let proposal_remove_115 =
                        ExternalProposal::new_remove(leaf_of_115, group_id, epoch, &cb.signature_key, sender_index)
                            .unwrap();

                    member_27
                        .context
                        .conversation_guard(&conv_id)
                        .await
                        .unwrap()
                        .decrypt_message(&proposal_remove_114_1.to_bytes().unwrap())
                        .await
                        .unwrap();
                    let result = member_27
                        .context
                        .conversation_guard(&conv_id)
                        .await
                        .unwrap()
                        .decrypt_message(&proposal_remove_114_2.to_bytes().unwrap())
                        .await;
                    assert!(matches!(
                        result.unwrap_err(),
                        Error::BufferedFutureMessage { message_epoch: 2 }
                    ));
                    member_27
                        .context
                        .conversation_guard(&conv_id)
                        .await
                        .unwrap()
                        .decrypt_message(&new_member_join_commit.to_bytes().unwrap())
                        .await
                        .unwrap();
                    member_27
                        .context
                        .conversation_guard(&conv_id)
                        .await
                        .unwrap()
                        .decrypt_message(&proposal_remove_115.to_bytes().unwrap())
                        .await
                        .unwrap();

                    member_27
                        .context
                        .conversation_guard(&conv_id)
                        .await
                        .unwrap()
                        .commit_pending_proposals()
                        .await
                        .unwrap();
                    let remove_two_members_commit = member_27.mls_transport.latest_commit().await;

                    // In this case, note that observer receives the proposal before the commit.
                    // This is the straightforward ordering and easy to deal with.
                    observer
                        .context
                        .conversation_guard(&conv_id)
                        .await
                        .unwrap()
                        .decrypt_message(&proposal_remove_115.to_bytes().unwrap())
                        .await
                        .unwrap();
                    observer
                        .context
                        .conversation_guard(&conv_id)
                        .await
                        .unwrap()
                        .decrypt_message(&remove_two_members_commit.to_bytes().unwrap())
                        .await
                        .unwrap();

                    // In this case, new_member receives the commit before the proposal. This means that
                    // the commit has to be buffered until the proposal it references is received.
                    let result = new_member
                        .context
                        .conversation_guard(&conv_id)
                        .await
                        .unwrap()
                        .decrypt_message(&remove_two_members_commit.to_bytes().unwrap())
                        .await;
                    assert!(matches!(result.unwrap_err(), Error::BufferedCommit));
                    new_member
                        .context
                        .conversation_guard(&conv_id)
                        .await
                        .unwrap()
                        .decrypt_message(&proposal_remove_115.to_bytes().unwrap())
                        .await
                        .unwrap();

                    observer.try_talk_to(&conv_id, &new_member).await.unwrap();
                    observer.try_talk_to(&conv_id, &member_27).await.unwrap();
                    new_member.try_talk_to(&conv_id, &member_27).await.unwrap();
                })
            },
        )
        .await
    }
}
