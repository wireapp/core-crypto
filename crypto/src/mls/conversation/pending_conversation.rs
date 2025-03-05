//! When a client joins a group via an external commit, it sometimes receives messages
//! (most of the time renewed external proposals) for the new epoch whereas it does not yet have
//! the confirmation from the DS that the external join commit has been accepted.

use super::Error;
use super::Result;
use crate::context::CentralContext;
use crate::mls::credential::crl::{extract_crl_uris_from_group, get_new_crl_distribution_points};
use crate::mls::credential::ext::CredentialExt as _;
use crate::prelude::{ConversationId, MlsConversationDecryptMessage};
use crate::{KeystoreError, LeafError, MlsError, RecursiveError};
use core_crypto_keystore::CryptoKeystoreMls as _;
use core_crypto_keystore::entities::{MlsPendingMessage, PersistedMlsPendingGroup};
use mls_crypto_provider::{CryptoKeystore, MlsCryptoProvider};
use openmls::credentials::CredentialWithKey;
use openmls::prelude::{MlsGroup, MlsMessageIn, MlsMessageInBody};
use tls_codec::Deserialize as _;

/// A pending conversation is a conversation that has been created via an external join commit
/// locally, while this commit has not yet been approved by the DS.
#[derive(Debug)]
pub struct PendingConversation {
    inner: PersistedMlsPendingGroup,
    context: CentralContext,
}

impl PendingConversation {
    pub(crate) fn new(inner: PersistedMlsPendingGroup, context: CentralContext) -> Self {
        Self { inner, context }
    }

    async fn mls_provider(&self) -> Result<MlsCryptoProvider> {
        self.context
            .mls_provider()
            .await
            .map_err(RecursiveError::root("getting mls provider"))
            .map_err(Into::into)
    }

    async fn keystore(&self) -> Result<CryptoKeystore> {
        let backend = self.mls_provider().await?;
        Ok(backend.keystore())
    }

    fn id(&self) -> &ConversationId {
        &self.inner.id
    }

    pub async fn try_process_own_join_commit(
        &self,
        message: impl AsRef<[u8]>,
    ) -> Result<MlsConversationDecryptMessage> {
        // If the confirmation tag of the pending group and this incoming message are identical, we can merge the pending group.
        if self.incoming_message_is_own_join_commit(message.as_ref()).await? {
            return self.merge_pending_group_and_build_decrypted_message_instance().await;
        }

        let keystore = self.keystore().await?;

        let pending_msg = MlsPendingMessage {
            foreign_id: self.id().clone(),
            message: message.as_ref().to_vec(),
        };
        keystore
            .save::<MlsPendingMessage>(pending_msg)
            .await
            .map_err(KeystoreError::wrap("saving mls pending message"))?;
        Err(Error::BufferedForPendingConversation)
    }

    /// If the message confirmation tag and the group confirmation tag are the same, it means that
    /// the external join commit has been accepted by the DS and the pending group can be merged.
    async fn incoming_message_is_own_join_commit(&self, message: impl AsRef<[u8]>) -> Result<bool> {
        let backend = self.mls_provider().await?;
        let keystore = backend.keystore();
        // Instantiate the pending group
        let (group, _cfg) = keystore
            .mls_pending_groups_load(self.id())
            .await
            .map_err(KeystoreError::wrap("loading mls pending groups"))?;
        let mut mls_group = core_crypto_keystore::deser::<MlsGroup>(&group)
            .map_err(KeystoreError::wrap("deserializing mls pending groups"))?;

        // The commit is only merged on this temporary instance of the pending group, to enable
        // calculation of the confirmation tag.
        mls_group
            .merge_pending_commit(&backend)
            .await
            .map_err(MlsError::wrap("merging pending commit"))?;
        let message_in = MlsMessageIn::tls_deserialize(&mut message.as_ref())
            .map_err(MlsError::wrap("deserializing mls message"))?;
        let MlsMessageInBody::PublicMessage(public_message) = message_in.extract() else {
            return Ok(false);
        };
        let Some(msg_ct) = public_message.confirmation_tag() else {
            return Ok(false);
        };
        let group_ct = mls_group
            .compute_confirmation_tag(&backend)
            .map_err(MlsError::wrap("computing confirmation tag"))?;
        Ok(*msg_ct == group_ct)
    }

    async fn merge_pending_group_and_build_decrypted_message_instance(&self) -> Result<MlsConversationDecryptMessage> {
        let context = &self.context;
        let backend = self.mls_provider().await?;
        let id = self.id();
        // TODO(SimonThormeyer): The implementation of that should be moved here
        let buffered_messages = context
            .merge_pending_group_from_external_commit(id)
            .await
            .map_err(RecursiveError::mls("merging pending group from external commit"))?;
        let conversation = context
            .get_conversation(self.id())
            .await
            .map_err(RecursiveError::mls_conversation("getting conversation by id"))?;
        let conversation = conversation.read().await;
        let own_leaf = conversation.group.own_leaf().ok_or(LeafError::InternalMlsError)?;

        // We return self identity here, probably not necessary to check revocation
        let own_leaf_credential_with_key = CredentialWithKey {
            credential: own_leaf.credential().clone(),
            signature_key: own_leaf.signature_key().clone(),
        };
        let identity = own_leaf_credential_with_key
            .extract_identity(conversation.ciphersuite(), None)
            .map_err(RecursiveError::mls_credential("extracting identity"))?;

        let crl_new_distribution_points = get_new_crl_distribution_points(
            &backend,
            extract_crl_uris_from_group(&conversation.group)
                .map_err(RecursiveError::mls_credential("extracting crl uris from group"))?,
        )
        .await
        .map_err(RecursiveError::mls_credential("getting new crl distribution points"))?;

        Ok(MlsConversationDecryptMessage {
            app_msg: None,
            proposals: vec![],
            is_active: conversation.group.is_active(),
            delay: conversation.compute_next_commit_delay(),
            sender_client_id: None,
            has_epoch_changed: true,
            identity,
            buffered_messages,
            crl_new_distribution_points,
        })
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
    async fn should_buffer_and_reapply_messages_after_external_commit_merged(case: TestCase) {
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
                    // Bob tries to join Alice's group with an external commit
                    let gi = alice_central.get_group_info(&id).await;
                    let external_commit = bob_central
                        .create_unmerged_external_commit(gi, case.custom_cfg(), case.credential_type)
                        .await;

                    // Alice decrypts the external commit...
                    alice_central
                        .context
                        .decrypt_message(&id, external_commit.commit.to_bytes().unwrap())
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
                        .decrypt_message(&id, external_proposal.to_bytes().unwrap())
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

                    // And now Bob will have to decrypt those messages while he hasn't yet merged its external commit
                    // To add more fun, he will buffer the messages in exactly the wrong order (to make
                    // sure he reapplies them in the right order afterwards)
                    let messages = vec![commit.commit, external_proposal, proposal]
                        .into_iter()
                        .map(|m| m.to_bytes().unwrap());
                    for m in messages {
                        let decrypt = bob_central.context.decrypt_message(&id, m).await;
                        assert!(matches!(decrypt.unwrap_err(), Error::BufferedForPendingConversation));
                    }
                    let decrypt = bob_central.context.decrypt_message(&id, app_msg).await;
                    assert!(matches!(decrypt.unwrap_err(), Error::BufferedForPendingConversation));

                    // Bob should have buffered the messages
                    assert_eq!(bob_central.context.count_entities().await.pending_messages, 4);

                    // Finally, Bob receives the green light from the DS and he can merge the external commit
                    let MlsConversationDecryptMessage {
                        buffered_messages: Some(restored_messages),
                        ..
                    } = bob_central
                        .context
                        .decrypt_message(&id, external_commit.commit.to_bytes().unwrap())
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
    async fn should_not_reapply_buffered_messages_when_external_commit_contains_remove(case: TestCase) {
        use crate::mls;

        run_test_with_client_ids(
            case.clone(),
            ["alice", "bob"],
            move |[alice_central, mut bob_central]| {
                Box::pin(async move {
                    let id = conversation_id();
                    alice_central
                        .context
                        .new_conversation(&id, case.credential_type, case.cfg.clone())
                        .await
                        .unwrap();
                    alice_central.invite_all(&case, &id, [&mut bob_central]).await.unwrap();

                    // Alice will never see this commit
                    bob_central
                        .context
                        .conversation_guard(&id)
                        .await
                        .unwrap()
                        .update_key_material()
                        .await
                        .unwrap();

                    let msg1 = bob_central
                        .context
                        .conversation_guard(&id)
                        .await
                        .unwrap()
                        .encrypt_message("A")
                        .await
                        .unwrap();
                    let msg2 = bob_central
                        .context
                        .conversation_guard(&id)
                        .await
                        .unwrap()
                        .encrypt_message("B")
                        .await
                        .unwrap();

                    // Since Alice missed Bob's commit she should buffer this message
                    let decrypt = alice_central.context.decrypt_message(&id, msg1).await;
                    assert!(matches!(
                        decrypt.unwrap_err(),
                        mls::conversation::Error::BufferedFutureMessage { .. }
                    ));
                    let decrypt = alice_central.context.decrypt_message(&id, msg2).await;
                    assert!(matches!(
                        decrypt.unwrap_err(),
                        mls::conversation::Error::BufferedFutureMessage { .. }
                    ));
                    assert_eq!(alice_central.context.count_entities().await.pending_messages, 2);

                    let gi = bob_central.get_group_info(&id).await;
                    alice_central
                        .context
                        .join_by_external_commit(gi, case.custom_cfg(), case.credential_type)
                        .await
                        .unwrap();

                    let ext_commit = alice_central.mls_transport.latest_commit_bundle().await;

                    bob_central
                        .context
                        .decrypt_message(&id, ext_commit.commit.to_bytes().unwrap())
                        .await
                        .unwrap();
                    // Alice should have deleted all her buffered messages
                    assert_eq!(alice_central.context.count_entities().await.pending_messages, 0);
                })
            },
        )
        .await
    }
}
