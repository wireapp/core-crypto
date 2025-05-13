//! Sometimes, while still in epoch `n`, we receive messages for epoch `n + 1`.
//! This is because our DS implementation doesn't guarantee that messages arrive in order.
//! This module deals with buffering these messages until we receive the commit that advances the
//! group epoch.

use super::{RecursionPolicy, Result};
use crate::KeystoreError;
use crate::mls::conversation::{ConversationGuard, ConversationWithMls, Error};
use crate::obfuscate::Obfuscated;
use crate::prelude::MlsBufferedConversationDecryptMessage;
use core_crypto_keystore::connection::FetchFromDatabase;
use core_crypto_keystore::entities::{EntityFindParams, MlsPendingMessage};
use log::{error, info};
use openmls::framing::{MlsMessageIn, MlsMessageInBody};
use openmls_traits::OpenMlsCryptoProvider as _;
use tls_codec::Deserialize;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum MessageRestorePolicy {
    /// Retrieve and decrypt pending messages, then clear them from the keystore.
    DecryptAndClear,
    /// Clear pending messages from the keystore without decrypting them.
    ClearOnly,
}

impl ConversationGuard {
    pub(super) async fn buffer_future_message(&self, message: impl AsRef<[u8]>) -> Result<()> {
        let backend = self.crypto_provider().await?;
        let keystore = backend.keystore();
        let conversation = self.conversation().await;
        let pending_msg = MlsPendingMessage {
            foreign_id: conversation.id().clone(),
            message: message.as_ref().to_vec(),
        };
        keystore
            .save::<MlsPendingMessage>(pending_msg)
            .await
            .map_err(KeystoreError::wrap("saving pending mls message"))?;
        Ok(())
    }

    pub(super) async fn restore_and_clear_pending_messages(
        &mut self,
    ) -> Result<Option<Vec<MlsBufferedConversationDecryptMessage>>> {
        let pending_messages = self
            .restore_pending_messages(MessageRestorePolicy::DecryptAndClear)
            .await?;

        if pending_messages.is_some() {
            let conversation = self.conversation().await;
            let backend = self.crypto_provider().await?;
            info!(group_id = Obfuscated::from(conversation.id()); "Clearing all buffered messages for conversation");
            backend
                .key_store()
                .remove::<MlsPendingMessage, _>(conversation.id())
                .await
                .map_err(KeystoreError::wrap("removing MlsPendingMessage from keystore"))?;
        }

        Ok(pending_messages)
    }

    #[cfg_attr(target_family = "wasm", async_recursion::async_recursion(?Send))]
    #[cfg_attr(not(target_family = "wasm"), async_recursion::async_recursion)]
    pub(crate) async fn restore_pending_messages(
        &mut self,
        policy: MessageRestorePolicy,
    ) -> Result<Option<Vec<MlsBufferedConversationDecryptMessage>>> {
        let result = async move {
            let conversation = self.conversation().await;
            let conversation_id = conversation.id();
            let backend = self.crypto_provider().await?;
            let keystore = backend.keystore();
            if policy == MessageRestorePolicy::ClearOnly {
                if keystore
                    .find::<MlsPendingMessage>(conversation_id)
                    .await
                    .map_err(KeystoreError::wrap("finding mls pending message by group id"))?
                    .is_some()
                {
                    keystore
                        .remove::<MlsPendingMessage, _>(conversation_id)
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
                .filter(|pm| pm.foreign_id == *conversation_id)
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

            info!(group_id = Obfuscated::from(conversation_id); "Attempting to restore {} buffered messages", pending_messages.len());

            // Need to drop conversation to allow borrowing `self` again.
            drop(conversation);

            let mut decrypted_messages = Vec::with_capacity(pending_messages.len());
            for (_, m) in pending_messages {
                let decrypted = self
                    .decrypt_message_inner(m, RecursionPolicy::None)
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
    use super::*;
    use crate::mls::conversation::Conversation as _;
    use crate::prelude::MlsConversationDecryptMessage;
    use crate::test_utils::*;
    use wasm_bindgen_test::*;

    wasm_bindgen_test_configure!(run_in_browser);

    #[apply(all_cred_cipher)]
    #[wasm_bindgen_test]
    async fn can_operate_with_pending_commit_wpb_17356(case: TestContext) {
        let [alice] = case.sessions().await;
        let id = conversation_id();
        alice
            .transaction
            .new_conversation(&id, case.credential_type, case.cfg.clone())
            .await
            .unwrap();
        // create a pending commit
        let _unmerged_commit = alice.create_unmerged_commit(&id).await;
        let mut conversation = alice.transaction.conversation(&id).await.unwrap();
        // This should work, even though there is a pending commit!
        assert!(conversation.conversation().await.group.pending_commit().is_some());
        conversation.update_key_material().await.unwrap();
        assert!(conversation.conversation().await.group.pending_commit().is_none());
    }

    #[apply(all_cred_cipher)]
    #[wasm_bindgen_test]
    async fn should_buffer_and_reapply_messages_after_commit_merged_for_sender(case: TestContext) {
        if case.is_pure_ciphertext() {
            // The use case tested here requires inspecting your own commit.
            // Openmls does not support this currently when protocol messages are encrypted.
            return;
        }

        let [alice_central, bob_central, charlie_central, debbie_central] = case.sessions().await;
        Box::pin(async move {
            let id = conversation_id();
            alice_central
                .transaction
                .new_conversation(&id, case.credential_type, case.cfg.clone())
                .await
                .unwrap();
            alice_central.invite_all(&case, &id, [&bob_central]).await.unwrap();

            // Bob creates a commit but won't merge it immediately (e.g, because his app crashes before he receives the success response from the ds)
            let unmerged_commit = bob_central.create_unmerged_commit(&id).await;

            // Alice decrypts the commit...
            alice_central
                .transaction
                .conversation(&id)
                .await
                .unwrap()
                .decrypt_message(unmerged_commit.commit.to_bytes().unwrap())
                .await
                .unwrap();

            // Meanwhile Debbie joins the party by creating an external proposal
            let epoch = alice_central.transaction.conversation(&id).await.unwrap().epoch().await;
            let external_proposal = debbie_central
                .transaction
                .new_external_add_proposal(id.clone(), epoch.into(), case.ciphersuite(), case.credential_type)
                .await
                .unwrap();

            // ...then Alice generates new messages for this epoch
            let app_msg = alice_central
                .transaction
                .conversation(&id)
                .await
                .unwrap()
                .encrypt_message(b"Hello Bob !")
                .await
                .unwrap();
            let proposal = alice_central
                .transaction
                .new_update_proposal(&id)
                .await
                .unwrap()
                .proposal;
            alice_central
                .transaction
                .conversation(&id)
                .await
                .unwrap()
                .decrypt_message(external_proposal.to_bytes().unwrap())
                .await
                .unwrap();
            let charlie = charlie_central.rand_key_package(&case).await;
            alice_central
                .transaction
                .conversation(&id)
                .await
                .unwrap()
                .add_members(vec![charlie])
                .await
                .unwrap();
            let commit = alice_central.mls_transport.latest_commit_bundle().await;
            charlie_central
                .transaction
                .process_welcome_message(commit.welcome.clone().unwrap().into(), case.custom_cfg())
                .await
                .unwrap();
            debbie_central
                .transaction
                .process_welcome_message(commit.welcome.clone().unwrap().into(), case.custom_cfg())
                .await
                .unwrap();

            // And now Bob will have to decrypt those messages while he hasn't yet merged its commit
            // To add more fun, he will buffer the messages in exactly the wrong order (to make
            // sure he reapplies them in the right order afterwards)
            let messages = [commit.commit, external_proposal, proposal]
                .into_iter()
                .map(|m| m.to_bytes().unwrap())
                .chain(std::iter::once(app_msg));
            for m in messages {
                let decrypt = bob_central
                    .transaction
                    .conversation(&id)
                    .await
                    .unwrap()
                    .decrypt_message(m)
                    .await;
                assert!(matches!(decrypt.unwrap_err(), Error::BufferedFutureMessage { .. }));
            }

            // Bob should have buffered the messages
            assert_eq!(bob_central.transaction.count_entities().await.pending_messages, 4);

            let observer = TestEpochObserver::new();
            bob_central
                .session()
                .await
                .register_epoch_observer(observer.clone())
                .await
                .unwrap();

            // Finally, Bob receives the green light from the DS and he can merge the external commit
            let MlsConversationDecryptMessage {
                buffered_messages: Some(restored_messages),
                ..
            } = bob_central
                .transaction
                .conversation(&id)
                .await
                .unwrap()
                .decrypt_message(unmerged_commit.commit.to_bytes().unwrap())
                .await
                .unwrap()
            else {
                panic!("Alice's messages should have been restored at this point");
            };

            for (idx, msg) in restored_messages.iter().enumerate() {
                if idx == 0 {
                    // this is the application message
                    assert_eq!(msg.app_msg.as_deref(), Some("Hello Bob !".as_bytes()));
                } else {
                    assert!(msg.app_msg.is_none());
                }
            }
            let observed_epochs = observer
                .observed_epochs()
                .await
                .into_iter()
                .map(|(_conversation_id, epoch)| epoch)
                .collect::<Vec<_>>();
            dbg!(&observed_epochs);
            assert_eq!(
                observed_epochs.len(),
                2,
                "there was 1 buffered commit changing the epoch plus the outer commit changing the epoch"
            );

            // because external commit got merged
            assert!(bob_central.try_talk_to(&id, &alice_central).await.is_ok());
            // because Alice's commit got merged
            assert!(bob_central.try_talk_to(&id, &charlie_central).await.is_ok());
            // because Debbie's external proposal got merged through the commit
            assert!(bob_central.try_talk_to(&id, &debbie_central).await.is_ok());

            // After merging we should erase all those pending messages
            assert_eq!(bob_central.transaction.count_entities().await.pending_messages, 0);
        })
        .await
    }

    #[apply(all_cred_cipher)]
    #[wasm_bindgen_test]
    async fn should_buffer_and_reapply_messages_after_commit_merged_for_receivers(case: TestContext) {
        if case.is_pure_ciphertext() {
            // The use case tested here requires inspecting your own commit.
            // Openmls does not support this currently when protocol messages are encrypted.
            return;
        }

        let [alice_central, bob_central, charlie_central, debbie_central] = case.sessions().await;
        Box::pin(async move {
            let id = conversation_id();
            alice_central
                .transaction
                .new_conversation(&id, case.credential_type, case.cfg.clone())
                .await
                .unwrap();

            // Bob joins the group with an external commit...
            let gi = alice_central.get_group_info(&id).await;
            bob_central
                .transaction
                .join_by_external_commit(gi, case.custom_cfg(), case.credential_type)
                .await
                .unwrap();

            let ext_commit = bob_central.mls_transport.latest_commit_bundle().await;

            // And before others had the chance to get the commit, Bob will create & send messages in the next epoch
            // which Alice will have to buffer until she receives the commit.
            // This simulates what the DS does with unordered messages
            let epoch = bob_central.transaction.conversation(&id).await.unwrap().epoch().await;
            let external_proposal = charlie_central
                .transaction
                .new_external_add_proposal(id.clone(), epoch.into(), case.ciphersuite(), case.credential_type)
                .await
                .unwrap();
            let app_msg = bob_central
                .transaction
                .conversation(&id)
                .await
                .unwrap()
                .encrypt_message(b"Hello Alice !")
                .await
                .unwrap();
            let proposal = bob_central.transaction.new_update_proposal(&id).await.unwrap().proposal;
            bob_central
                .transaction
                .conversation(&id)
                .await
                .unwrap()
                .decrypt_message(external_proposal.to_bytes().unwrap())
                .await
                .unwrap();
            let debbie = debbie_central.rand_key_package(&case).await;
            bob_central
                .transaction
                .conversation(&id)
                .await
                .unwrap()
                .add_members(vec![debbie])
                .await
                .unwrap();
            let commit = bob_central.mls_transport.latest_commit_bundle().await;
            charlie_central
                .transaction
                .process_welcome_message(commit.welcome.clone().unwrap().into(), case.custom_cfg())
                .await
                .unwrap();
            debbie_central
                .transaction
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
                    .transaction
                    .conversation(&id)
                    .await
                    .unwrap()
                    .decrypt_message(m)
                    .await;
                assert!(matches!(decrypt.unwrap_err(), Error::BufferedFutureMessage { .. }));
            }
            let decrypt = alice_central
                .transaction
                .conversation(&id)
                .await
                .unwrap()
                .decrypt_message(app_msg)
                .await;
            assert!(matches!(decrypt.unwrap_err(), Error::BufferedFutureMessage { .. }));

            // Alice should have buffered the messages
            assert_eq!(alice_central.transaction.count_entities().await.pending_messages, 4);

            let observer = TestEpochObserver::new();
            alice_central
                .session()
                .await
                .register_epoch_observer(observer.clone())
                .await
                .unwrap();

            // Finally, Alice receives the original commit for this epoch
            let original_commit = ext_commit.commit.to_bytes().unwrap();
            let MlsConversationDecryptMessage {
                buffered_messages: Some(restored_messages),
                ..
            } = alice_central
                .transaction
                .conversation(&id)
                .await
                .unwrap()
                .decrypt_message(original_commit)
                .await
                .unwrap()
            else {
                panic!("Bob's messages should have been restored at this point");
            };
            for (idx, msg) in restored_messages.into_iter().enumerate() {
                if idx == 0 {
                    assert_eq!(msg.app_msg.as_deref(), Some(b"Hello Alice !" as _));
                } else {
                    assert!(msg.app_msg.is_none());
                }
            }

            let observed_epochs = observer
                .observed_epochs()
                .await
                .into_iter()
                .map(|(_conversation_id, epoch)| epoch)
                .collect::<Vec<_>>();
            dbg!(&observed_epochs);
            assert_eq!(
                observed_epochs.len(),
                2,
                "there was 1 buffered commit changing the epoch plus the outer commit changing the epoch"
            );

            // because external commit got merged
            assert!(alice_central.try_talk_to(&id, &bob_central).await.is_ok());
            // because Alice's commit got merged
            assert!(alice_central.try_talk_to(&id, &charlie_central).await.is_ok());
            // because Debbie's external proposal got merged through the commit
            assert!(alice_central.try_talk_to(&id, &debbie_central).await.is_ok());

            // After merging we should erase all those pending messages
            assert_eq!(alice_central.transaction.count_entities().await.pending_messages, 0);
        })
        .await
    }

    /// Replicating [WPB-15810]
    ///
    /// [WPB-15810]: https://wearezeta.atlassian.net/browse/WPB-15810
    #[apply(all_cred_cipher)]
    async fn wpb_15810(case: TestContext) {
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

        let [external_0, new_member, member_27, observer, member_114, member_115] = case.sessions().await;
        Box::pin(async move {
            // scenario start: everyone except "new_member" is in the conversation
            let conv_id = conversation_id();

            // set up external_0 as the backend / delivery service
            let signature_key = external_0.client_signature_key(&case).await.as_slice().to_vec();
            let mut config = case.cfg.clone();
            observer
                .transaction
                .set_raw_external_senders(&mut config, vec![signature_key])
                .await
                .unwrap();

            // create and initialize the conversation
            observer
                .transaction
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
            let proposal_remove_114_1 =
                ExternalProposal::new_remove(leaf_of_114, group_id.clone(), epoch, &cb.signature_key, sender_index)
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
                .transaction
                .conversation(&conv_id)
                .await
                .unwrap()
                .decrypt_message(&proposal_remove_114_1.to_bytes().unwrap())
                .await
                .unwrap();
            println!("observer executing second proposal");
            let result = observer
                .transaction
                .conversation(&conv_id)
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
                .transaction
                .conversation(&conv_id)
                .await
                .unwrap()
                .decrypt_message(&new_member_join_commit.to_bytes().unwrap())
                .await
                .unwrap();

            // now the new member receives the messages in order
            println!("new_member executing first proposal");
            assert!(matches!(
                new_member
                    .transaction
                    .conversation(&conv_id)
                    .await
                    .unwrap()
                    .decrypt_message(&proposal_remove_114_1.to_bytes().unwrap())
                    .await
                    .unwrap_err(),
                mls::conversation::Error::StaleProposal,
            ));
            println!("new_member executing second proposal");
            new_member
                .transaction
                .conversation(&conv_id)
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
                ExternalProposal::new_remove(leaf_of_115, group_id, epoch, &cb.signature_key, sender_index).unwrap();

            member_27
                .transaction
                .conversation(&conv_id)
                .await
                .unwrap()
                .decrypt_message(&proposal_remove_114_1.to_bytes().unwrap())
                .await
                .unwrap();
            let result = member_27
                .transaction
                .conversation(&conv_id)
                .await
                .unwrap()
                .decrypt_message(&proposal_remove_114_2.to_bytes().unwrap())
                .await;
            assert!(matches!(
                result.unwrap_err(),
                Error::BufferedFutureMessage { message_epoch: 2 }
            ));
            member_27
                .transaction
                .conversation(&conv_id)
                .await
                .unwrap()
                .decrypt_message(&new_member_join_commit.to_bytes().unwrap())
                .await
                .unwrap();
            member_27
                .transaction
                .conversation(&conv_id)
                .await
                .unwrap()
                .decrypt_message(&proposal_remove_115.to_bytes().unwrap())
                .await
                .unwrap();

            member_27
                .transaction
                .conversation(&conv_id)
                .await
                .unwrap()
                .commit_pending_proposals()
                .await
                .unwrap();
            let remove_two_members_commit = member_27.mls_transport.latest_commit().await;

            // In this case, note that observer receives the proposal before the commit.
            // This is the straightforward ordering and easy to deal with.
            observer
                .transaction
                .conversation(&conv_id)
                .await
                .unwrap()
                .decrypt_message(&proposal_remove_115.to_bytes().unwrap())
                .await
                .unwrap();
            observer
                .transaction
                .conversation(&conv_id)
                .await
                .unwrap()
                .decrypt_message(&remove_two_members_commit.to_bytes().unwrap())
                .await
                .unwrap();

            // In this case, new_member receives the commit before the proposal. This means that
            // the commit has to be buffered until the proposal it references is received.
            let result = new_member
                .transaction
                .conversation(&conv_id)
                .await
                .unwrap()
                .decrypt_message(&remove_two_members_commit.to_bytes().unwrap())
                .await;
            assert!(matches!(result.unwrap_err(), Error::BufferedCommit));
            new_member
                .transaction
                .conversation(&conv_id)
                .await
                .unwrap()
                .decrypt_message(&proposal_remove_115.to_bytes().unwrap())
                .await
                .unwrap();

            observer.try_talk_to(&conv_id, &new_member).await.unwrap();
            observer.try_talk_to(&conv_id, &member_27).await.unwrap();
            new_member.try_talk_to(&conv_id, &member_27).await.unwrap();
        })
        .await
    }
}
