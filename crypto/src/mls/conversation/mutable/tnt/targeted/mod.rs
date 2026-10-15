mod decrypt;
pub(super) mod encrypt;

use const_format::concatcp;
use derive_more::Constructor;
use openmls::{
    group::{GroupEpoch, GroupId, MlsGroup, group_context::GroupContext},
    prelude::{HpkeCiphertext, LeafNodeIndex},
};
use openmls_traits::OpenMlsCryptoProvider;
use tls_codec::{Serialize as _, TlsDeserialize, TlsSerialize, TlsSize};

use self::encrypt::TargetedMessagePolicy;
use super::{ProtocolVersion, Result, tnt_message_counter::TntMessageCounter};
use crate::{OpenMlsError, TlsCodecError};

/// Used to parameterize HPKE Seal/Open.
/// Not carried with the payload, constructed freshly when decrypting.
#[derive(TlsSize, TlsSerialize, derive_more::Constructor)]
pub(super) struct TargetedMessageContext {
    protocol_version: ProtocolVersion,
    policy: TargetedMessagePolicy,
    sender: LeafNodeIndex,
    recipient: LeafNodeIndex,
    group_context: GroupContext,
}

impl TargetedMessageContext {
    fn new_with_current_protocol_version(
        policy: TargetedMessagePolicy,
        group_context: &GroupContext,
        sender: LeafNodeIndex,
        recipient: LeafNodeIndex,
    ) -> Self {
        Self {
            policy,
            protocol_version: ProtocolVersion::CURRENT,
            sender,
            recipient,
            group_context: group_context.clone(),
        }
    }
}

/// Used to parametrize HPKE Seal/Open
#[derive(Constructor, TlsSize, TlsSerialize)]
pub(super) struct PskId {
    group_id: GroupId,
    epoch: GroupEpoch,
}

/// Targeted messages are messages distributed to individual clients. They don't mutate regular group state (i.e, as
/// defined by RFC 9420). That is because many or most clients in a group will never receive those messages, and will
/// not have the appropriate cryptographic state to decrypt the messages.
///
/// Any feature using a targeted, transient or transient targeted message MUST specify why the lower security
/// guarantees (compared to MLS application messages) are acceptable and/or how they are mitigated.
///
/// Implementation note: we're preferring OpenMLS types here, because we're using OpenMLS encoding. Once we switch to
/// mls-rs, we're going to use mls-rs types.
#[derive(TlsSize, TlsSerialize, TlsDeserialize, Constructor)]
pub(super) struct TargetedMessage {
    counter: TntMessageCounter,
    sender: LeafNodeIndex,
    recipient: LeafNodeIndex,
    /// Client ID as it appears in credentials.
    recipient_id: Vec<u8>,
    pub(super) epoch: GroupEpoch,
    group_id: GroupId,
    /// Encrypted with the receipient's HPKE public key; authenticated with a PSK derived from the epoch secret,
    /// guaranteeing that the sender was a member of the group during the epoch. An additional authentication layer is
    /// provided by the signature over the entire message. Before encryption, the HPKE plaintext is padded.
    payload: HpkeCiphertext,
}

impl TargetedMessage {
    pub(super) const SIGN_LABEL_PERSISTED: &str =
        concatcp!("TntMessageTBS-Persisted-Targeted v", ProtocolVersion::CURRENT.as_u16());
    pub(super) const SIGN_LABEL_TRANSIENT: &str =
        concatcp!("TntMessageTBS-Transient-Targeted v", ProtocolVersion::CURRENT.as_u16());
    pub(super) const PSK_LABEL: &str = concatcp!("Tnt TargetedMessage Psk v", ProtocolVersion::CURRENT.as_u16());

    pub(super) fn sender(&self) -> LeafNodeIndex {
        self.sender
    }
}

/// The data that is extracted from the MLS group when encrypting or decrypting a targeted message.
struct HpkeContextData {
    info: Vec<u8>,
    psk_id: Vec<u8>,
    psk: zeroize::Zeroizing<Vec<u8>>,
}

fn extract_hpke_context_data(
    crypto_provider: &impl OpenMlsCryptoProvider,
    context: &TargetedMessageContext,
    mls_group: &MlsGroup,
) -> Result<HpkeContextData> {
    let info = context
        .tls_serialize_detached()
        .map_err(TlsCodecError::serialize("TargetedMessageContext"))?;

    let psk = derive_targeted_message_psk(crypto_provider, mls_group)?;
    let psk_id = PskId::new(mls_group.group_id().clone(), mls_group.epoch());
    let psk_id = psk_id
        .tls_serialize_detached()
        .map_err(TlsCodecError::serialize("PskId"))?;

    Ok(HpkeContextData { info, psk_id, psk })
}

fn derive_targeted_message_psk(
    crypto_provider: &impl OpenMlsCryptoProvider,
    mls_group: &MlsGroup,
) -> Result<zeroize::Zeroizing<Vec<u8>>> {
    let cipher_suite = mls_group.ciphersuite();
    // We can use an empty context because we're using a unique label.
    mls_group
        .export_secret(
            crypto_provider,
            TargetedMessage::PSK_LABEL,
            &[],
            cipher_suite.hash_length(),
        )
        .map(zeroize::Zeroizing::new)
        .map_err(OpenMlsError::wrap("exporting targeted message psk"))
        .map_err(Into::into)
}

#[cfg(test)]
mod tests {
    use core_crypto_keystore::{
        entities::{OldEpochData, OldEpochDataPkRef},
        traits::{EntityDeleteBorrowed as _, FetchFromDatabase as _},
    };
    use openmls::prelude::{GroupEpoch, Signable as _};
    use tls_codec::{Deserialize as _, Serialize as _};

    use super::TargetedMessagePolicy;
    use crate::{
        CertificateBundle, Credential, CredentialRef,
        mls::conversation::{
            ConversationMut, Error,
            mutable::tnt::{TntMessage, TntMessageBody},
        },
        test_utils::*,
    };

    /// The leaf index `member` occupies in its own view of the conversation.
    async fn leaf_index_of(conversation: &TestConversation<'_>, member: &SessionContext) -> u32 {
        conversation.guard_of(member).await.group().await.own_leaf_index().u32()
    }

    /// Rewrite a targeted message so that it claims to have been sent in `epoch`, and re-sign it with the
    /// current signature key of `signer`.
    ///
    /// The result carries a valid signature by `signer`. Anything which rejects it has therefore checked
    /// the signature against someone else's key, or has not found a sender at all.
    async fn backdate(encrypted: &[u8], epoch: u64, signer: &ConversationMut) -> Vec<u8> {
        let TntMessage { mut content, .. } = TntMessage::tls_deserialize_exact(encrypted).unwrap();
        let TntMessageBody::Targeted(targeted) = &mut content.body else {
            panic!("expected a persisted targeted message");
        };
        targeted.epoch = GroupEpoch::from(epoch);

        let credential = signer.find_current_credential().await.unwrap();
        let resigned: TntMessage = content.sign(credential.signature_key()).unwrap();
        resigned.tls_serialize_detached().unwrap()
    }

    #[apply(all_cred_cipher)]
    async fn can_decrypt_targeted_message(case: TestContext) {
        let [alice, bob] = case.sessions().await;
        let conversation = case.create_conversation([&alice, &bob]).await;

        let message = b"This persisted message targets Bob";
        let recipient = bob.get_client_id().await;
        let encrypted = conversation
            .guard()
            .await
            .encrypt_targeted(&recipient, TargetedMessagePolicy::Persisted, message.to_vec())
            .await
            .unwrap();
        assert_ne!(&message, &encrypted.as_slice());

        let decrypted = conversation
            .guard_of(&bob)
            .await
            .decrypt_message(encrypted)
            .await
            .unwrap()
            .into_persisted_targeted()
            .unwrap()
            .plaintext;

        assert_eq!(&decrypted, &message);

        let message = b"This transient message targets Bob";
        let recipient = bob.get_client_id().await;
        let encrypted = conversation
            .guard()
            .await
            .encrypt_targeted(&recipient, TargetedMessagePolicy::Transient, message.to_vec())
            .await
            .unwrap();
        assert_ne!(&message, &encrypted.as_slice());

        let decrypted = conversation
            .guard_of(&bob)
            .await
            .decrypt_message(encrypted)
            .await
            .unwrap()
            .into_transient_targeted()
            .unwrap()
            .plaintext;

        assert_eq!(&decrypted, &message);
    }

    #[apply(all_cred_cipher)]
    async fn can_decrypt_targeted_message_from_past_epoch(case: TestContext) {
        let [alice, bob] = case.sessions().await;
        let mut conversation = case.create_conversation([&alice, &bob]).await;
        let recipient = bob.get_client_id().await;

        // Bob will decrypt this message before advancing more than MAX_PAST_EPOCHS
        let within_retention = conversation
            .guard()
            .await
            .encrypt_targeted(
                &recipient,
                TargetedMessagePolicy::Persisted,
                b"within retention".to_vec(),
            )
            .await
            .unwrap();

        // Bob will fail to decrypt this message after advancing MAX_PAST_EPOCHS + 1
        let beyond_retention = conversation
            .guard()
            .await
            .encrypt_targeted(
                &recipient,
                TargetedMessagePolicy::Persisted,
                b"beyond retention".to_vec(),
            )
            .await
            .unwrap();

        for _ in 0..crate::mls::conversation::config::MAX_PAST_EPOCHS {
            conversation = conversation.acting_as(&bob).await.update_notify().await;
        }

        let decrypted = conversation
            .guard_of(&bob)
            .await
            .decrypt_message(within_retention)
            .await
            .unwrap()
            .into_persisted_targeted()
            .unwrap();
        assert_eq!(decrypted.plaintext, b"within retention");

        // MAX_PAST_EPOCHS + 1
        conversation = conversation.acting_as(&bob).await.update_notify().await;

        let error = conversation
            .guard_of(&bob)
            .await
            .decrypt_message(beyond_retention)
            .await
            .unwrap_err();
        assert!(matches!(error, crate::mls::conversation::Error::MessageEpochTooOld));
    }

    #[apply(all_cred_cipher)]
    async fn cant_decrypt_same_targeted_message_twice(case: TestContext) {
        let [alice, bob] = case.sessions().await;
        let conversation = case.create_conversation([&alice, &bob]).await;

        let message = b"This persisted message targets Bob";
        let recipient = bob.get_client_id().await;
        let encrypted = conversation
            .guard()
            .await
            .encrypt_targeted(&recipient, TargetedMessagePolicy::Persisted, message.to_vec())
            .await
            .unwrap();
        assert_ne!(&message, &encrypted.as_slice());

        let decrypted = conversation
            .guard_of(&bob)
            .await
            .decrypt_message(&encrypted)
            .await
            .unwrap()
            .into_persisted_targeted()
            .unwrap()
            .plaintext;

        assert_eq!(&decrypted, &message);

        let error = conversation
            .guard_of(&bob)
            .await
            .decrypt_message(encrypted)
            .await
            .unwrap_err();
        assert!(matches!(error, crate::mls::conversation::Error::DuplicateMessage));
    }

    #[apply(all_cred_cipher)]
    async fn can_buffer_targeted_message(case: TestContext) {
        let [alice, bob] = case.sessions().await;
        let conversation = case.create_conversation([&alice, &bob]).await;

        let epoch_1 = b"This persisted message targets Bob in epoch 1";
        let recipient = bob.get_client_id().await;
        let encrypted_epoch_1 = conversation
            .guard()
            .await
            .encrypt_targeted(&recipient, TargetedMessagePolicy::Persisted, epoch_1.to_vec())
            .await
            .unwrap();
        assert_ne!(&epoch_1, &encrypted_epoch_1.as_slice());

        let commit = conversation.update().await;

        let epoch_2 = b"This persisted message targets Bob in epoch 2";
        let conversation = commit.conversation();
        let encrypted_epoch_2 = conversation
            .guard()
            .await
            .encrypt_targeted(&recipient, TargetedMessagePolicy::Persisted, epoch_2.to_vec())
            .await
            .unwrap();
        assert_ne!(&epoch_2, &encrypted_epoch_2.as_slice());

        let decrypted = conversation
            .guard_of(&bob)
            .await
            .decrypt_message(encrypted_epoch_1)
            .await
            .unwrap()
            .into_persisted_targeted()
            .unwrap()
            .plaintext;
        assert_eq!(&decrypted, &epoch_1);

        let error = conversation
            .guard_of(&bob)
            .await
            .decrypt_message(encrypted_epoch_2)
            .await
            .unwrap_err();
        assert!(matches!(
            error,
            crate::mls::conversation::Error::BufferedFutureMessage { message_epoch: 2 }
        ));

        let (_, decrypted_commit) = commit.notify_member_fallible(&bob).await;
        let decrypted_commit = decrypted_commit.unwrap().into_commit().unwrap();
        let buffered_message = decrypted_commit.buffered_messages.unwrap().remove(0);
        let decrypted = crate::DecryptedMessage::from(buffered_message)
            .into_persisted_targeted()
            .unwrap()
            .plaintext;
        assert_eq!(&decrypted, &epoch_2);
    }

    #[apply(all_cred_cipher)]
    async fn targeted_message_survives_its_senders_leaf_being_reused(case: TestContext) {
        let [alice, bob, charlie, dave] = case.sessions().await;
        let conversation = case.create_conversation([&alice, &bob, &charlie]).await;
        let charlie_id = charlie.get_client_id().await;
        let charlie_leaf = leaf_index_of(&conversation, &charlie).await;

        let message = b"sent by charlie before leaving";
        let encrypted = conversation
            .guard_of(&charlie)
            .await
            .encrypt_targeted(
                &bob.get_client_id().await,
                TargetedMessagePolicy::Persisted,
                message.to_vec(),
            )
            .await
            .unwrap();

        let conversation = conversation.remove_notify(&charlie).await;
        let conversation = conversation.invite_notify([&dave]).await;
        assert_eq!(
            leaf_index_of(&conversation, &dave).await,
            charlie_leaf,
            "the test is only meaningful if dave now holds charlie's old leaf"
        );

        let decrypted = conversation
            .guard_of(&bob)
            .await
            .decrypt_message(encrypted)
            .await
            .unwrap()
            .into_persisted_targeted()
            .unwrap();
        assert_eq!(decrypted.plaintext, message);
        assert_eq!(
            decrypted.sender_client_id, charlie_id,
            "the message must be attributed to whoever held the leaf in the epoch it was sent"
        );
    }

    #[apply(all_cred_cipher)]
    async fn targeted_message_survives_its_senders_removal(case: TestContext) {
        let [alice, bob, charlie] = case.sessions().await;
        let conversation = case.create_conversation([&alice, &bob, &charlie]).await;
        let charlie_id = charlie.get_client_id().await;

        let message = b"sent by charlie before leaving";
        let encrypted = conversation
            .guard_of(&charlie)
            .await
            .encrypt_targeted(
                &bob.get_client_id().await,
                TargetedMessagePolicy::Persisted,
                message.to_vec(),
            )
            .await
            .unwrap();

        let conversation = conversation.remove_notify(&charlie).await;

        let decrypted = conversation
            .guard_of(&bob)
            .await
            .decrypt_message(encrypted)
            .await
            .unwrap()
            .into_persisted_targeted()
            .unwrap();
        assert_eq!(decrypted.plaintext, message);
        assert_eq!(decrypted.sender_client_id, charlie_id);
    }

    #[apply(all_cred_cipher)]
    async fn targeted_message_survives_its_sender_rotating_their_signature_key(case: TestContext) {
        // Rotating a basic credential is not supported for now. A new basic credential for the same client compares
        // equal to the old one, so `set_credential_inner` keeps the old leaf and the update commit is signed with a
        // key that leaf does not hold.
        if case.is_basic() {
            return;
        }

        let [alice, bob] = case.sessions().await;
        let conversation = case.create_conversation([&alice, &bob]).await;
        let alice_id = alice.get_client_id().await;

        let message = b"signed with alice's first key";
        let encrypted = conversation
            .guard()
            .await
            .encrypt_targeted(
                &bob.get_client_id().await,
                TargetedMessagePolicy::Persisted,
                message.to_vec(),
            )
            .await
            .unwrap();

        let intermediate_ca = alice.x509_chain_unchecked().find_local_intermediate_ca();
        let certificate = CertificateBundle::rand(&alice_id, intermediate_ca);
        let new_credential = Credential::x509(case.cipher_suite(), certificate).unwrap();
        let new_credential = alice
            .transaction
            .add_credential_without_clientid_check(new_credential)
            .unwrap();
        let old_key = conversation.guard().await.find_current_credential().await.unwrap();
        let conversation = conversation
            .set_credential_by_ref_notify(&CredentialRef::from_credential(&new_credential))
            .await;
        let new_key = conversation.guard().await.find_current_credential().await.unwrap();
        assert_ne!(
            old_key.signature_key().public(),
            new_key.signature_key().public(),
            "the test is only meaningful if alice's signature key has changed"
        );

        let decrypted = conversation
            .guard_of(&bob)
            .await
            .decrypt_message(encrypted)
            .await
            .unwrap()
            .into_persisted_targeted()
            .unwrap();
        assert_eq!(decrypted.plaintext, message);
        assert_eq!(
            decrypted.sender_client_id, alice_id,
            "the message must be attributed to the credential alice used when she sent it"
        );
    }

    #[apply(all_cred_cipher)]
    async fn targeted_message_survives_its_recipient_rejoining_at_another_leaf(case: TestContext) {
        let [alice, charlie, bob] = case.sessions().await;
        let conversation = case.create_conversation([&alice, &charlie, &bob]).await;
        let bob_leaf_before = leaf_index_of(&conversation, &bob).await;

        let message = b"sent to bob's first leaf";
        let encrypted = conversation
            .guard()
            .await
            .encrypt_targeted(
                &bob.get_client_id().await,
                TargetedMessagePolicy::Persisted,
                message.to_vec(),
            )
            .await
            .unwrap();

        // Charlie's departure leaves a blank leaf to the left of bob's, which bob's rejoin will take.
        let conversation = conversation.remove_notify(&charlie).await;
        let conversation = conversation.external_join_notify(&bob).await;
        assert_ne!(
            leaf_index_of(&conversation, &bob).await,
            bob_leaf_before,
            "the test is only meaningful if bob's rejoin moved him to another leaf"
        );

        let decrypted = conversation
            .guard_of(&bob)
            .await
            .decrypt_message(encrypted)
            .await
            .unwrap()
            .into_persisted_targeted()
            .unwrap();
        assert_eq!(decrypted.plaintext, message);
    }

    #[apply(all_cred_cipher)]
    async fn targeted_message_from_the_epoch_a_rejoin_left_can_be_decrypted(case: TestContext) {
        let [alice, bob] = case.sessions().await;
        let conversation = case.create_conversation([&alice, &bob]).await;

        let message = b"sent in the epoch bob is about to abandon";
        let encrypted = conversation
            .guard()
            .await
            .encrypt_targeted(
                &bob.get_client_id().await,
                TargetedMessagePolicy::Persisted,
                message.to_vec(),
            )
            .await
            .unwrap();

        let conversation = conversation.external_join_notify(&bob).await;

        let decrypted = conversation
            .guard_of(&bob)
            .await
            .decrypt_message(encrypted)
            .await
            .unwrap()
            .into_persisted_targeted()
            .unwrap();
        assert_eq!(decrypted.plaintext, message);
    }

    /// A rejoin must not lose the epoch it leaves, even when the recipient entered that epoch by commit and did
    /// nothing else in it.
    ///
    /// Unlike the epoch a conversation is created in, an epoch entered by commit has no other chance to be recorded
    /// before the rejoin replaces the group.
    #[apply(all_cred_cipher)]
    async fn targeted_message_from_an_epoch_entered_by_commit_survives_a_rejoin(case: TestContext) {
        let [alice, bob] = case.sessions().await;
        let conversation = case.create_conversation([&alice, &bob]).await;
        let joined_epoch = conversation.guard_of(&bob).await.epoch().await;

        let conversation = conversation.update_notify().await;
        assert!(
            conversation.guard_of(&bob).await.epoch().await > joined_epoch,
            "the test is only meaningful if bob entered the sending epoch by commit"
        );

        let message = b"sent in an epoch bob entered by commit and is about to abandon";
        let encrypted = conversation
            .guard()
            .await
            .encrypt_targeted(
                &bob.get_client_id().await,
                TargetedMessagePolicy::Persisted,
                message.to_vec(),
            )
            .await
            .unwrap();

        let conversation = conversation.external_join_notify(&bob).await;

        let decrypted = conversation
            .guard_of(&bob)
            .await
            .decrypt_message(encrypted)
            .await
            .unwrap()
            .into_persisted_targeted()
            .unwrap();
        assert_eq!(decrypted.plaintext, message);
    }

    /// A rejoin must not lose the epoch it leaves, even when nothing about that epoch was recorded yet.
    ///
    /// This is the state of every conversation which existed before old epoch data was introduced: its current epoch
    /// has no row until something records one. Deleting the row reproduces that.
    #[apply(all_cred_cipher)]
    async fn targeted_message_from_an_unrecorded_epoch_survives_a_rejoin(case: TestContext) {
        let [alice, bob] = case.sessions().await;
        let conversation = case.create_conversation([&alice, &bob]).await;

        let epoch = conversation.guard_of(&bob).await.epoch().await;
        let deleted = OldEpochData::delete_borrowed(
            bob.transaction.inner().unwrap().transaction(),
            OldEpochDataPkRef::new(conversation.id().keystore(), epoch),
        )
        .unwrap();
        assert!(
            deleted,
            "the test is only meaningful if bob's current epoch was recorded"
        );

        let message = b"sent in an epoch bob has no record of";
        let encrypted = conversation
            .guard()
            .await
            .encrypt_targeted(
                &bob.get_client_id().await,
                TargetedMessagePolicy::Persisted,
                message.to_vec(),
            )
            .await
            .unwrap();

        let conversation = conversation.external_join_notify(&bob).await;

        let decrypted = conversation
            .guard_of(&bob)
            .await
            .decrypt_message(encrypted)
            .await
            .unwrap()
            .into_persisted_targeted()
            .unwrap();
        assert_eq!(decrypted.plaintext, message);
    }

    /// A rejoin landing on an epoch number the recipient already has a record of must replace that record.
    ///
    /// Epoch numbers only identify an epoch within one history of the group. Here bob follows a fork of the group
    /// which charlie never sees, then rejoins from charlie's state. The epoch number bob rejoins at is one he already
    /// recorded in the fork, and that record describes the wrong epoch.
    #[apply(all_cred_cipher)]
    async fn targeted_message_survives_a_rejoin_onto_an_epoch_number_seen_in_a_fork(case: TestContext) {
        let [alice, bob, charlie] = case.sessions().await;
        let conversation = case.create_conversation([&alice, &bob, &charlie]).await;
        let conversation = conversation.acting_as(&charlie).await;
        let charlies_group_info = conversation.export_group_info().await;

        // Alice's commit reaches bob but never charlie, so alice and bob are now on a fork of charlie's group.
        let conversation = conversation
            .acting_as(&alice)
            .await
            .update()
            .await
            .notify_member(&bob)
            .await
            .finish();
        let forked_epoch = conversation.guard_of(&bob).await.epoch().await;

        // Bob acts in the fork, so it is recorded however recording on entry to an epoch turns out.
        conversation
            .guard_of(&bob)
            .await
            .encrypt_targeted(
                &alice.get_client_id().await,
                TargetedMessagePolicy::Persisted,
                b"recorded in the fork".to_vec(),
            )
            .await
            .unwrap();
        let forked_record = bob
            .database()
            .get_borrowed::<OldEpochData>(OldEpochDataPkRef::new(conversation.id().keystore(), forked_epoch))
            .await
            .unwrap();
        assert!(
            forked_record.is_some(),
            "the test is only meaningful if bob recorded the forked epoch"
        );

        let conversation = conversation
            .acting_as(&charlie)
            .await
            .external_join_via_group_info(&bob, charlies_group_info)
            .await
            .notify_member(&charlie)
            .await
            .finish();
        assert_eq!(
            conversation.guard_of(&bob).await.epoch().await,
            forked_epoch,
            "the test is only meaningful if bob rejoined at the epoch number he recorded in the fork"
        );

        let message = b"sent in the epoch bob rejoined at";
        let encrypted = conversation
            .guard_of(&charlie)
            .await
            .encrypt_targeted(
                &bob.get_client_id().await,
                TargetedMessagePolicy::Persisted,
                message.to_vec(),
            )
            .await
            .unwrap();

        let conversation = conversation
            .acting_as(&charlie)
            .await
            .update()
            .await
            .notify_member(&bob)
            .await
            .finish();

        let decrypted = conversation
            .guard_of(&bob)
            .await
            .decrypt_message(encrypted)
            .await
            .unwrap()
            .into_persisted_targeted()
            .unwrap();
        assert_eq!(decrypted.plaintext, message);
    }

    #[apply(all_cred_cipher)]
    async fn backdated_message_from_a_reused_leaf_fails_signature_verification(case: TestContext) {
        let [alice, bob, charlie, dave] = case.sessions().await;
        let conversation = case.create_conversation([&alice, &bob, &charlie]).await;
        let charlie_leaf = leaf_index_of(&conversation, &charlie).await;
        let charlies_epoch = conversation.guard().await.epoch().await;

        let conversation = conversation.remove_notify(&charlie).await;
        let conversation = conversation.invite_notify([&dave]).await;
        assert_eq!(
            leaf_index_of(&conversation, &dave).await,
            charlie_leaf,
            "the test is only meaningful if dave now holds charlie's old leaf"
        );

        let encrypted = conversation
            .guard_of(&dave)
            .await
            .encrypt_targeted(
                &bob.get_client_id().await,
                TargetedMessagePolicy::Persisted,
                b"dave pretending to be charlie".to_vec(),
            )
            .await
            .unwrap();
        let forged = backdate(&encrypted, charlies_epoch, &conversation.guard_of(&dave).await).await;

        let error = conversation
            .guard_of(&bob)
            .await
            .decrypt_message(forged)
            .await
            .unwrap_err();
        assert!(
            matches!(
                error,
                Error::OpenMls(crate::OpenMlsError {
                    context: "verifying tnt message signature",
                    ..
                })
            ),
            "a message claiming an old epoch must be verified against that epoch's occupant of the leaf, got {error:?}"
        );
    }

    #[apply(all_cred_cipher)]
    async fn backdated_message_from_before_the_sender_joined_is_rejected(case: TestContext) {
        let [alice, bob, charlie] = case.sessions().await;
        let conversation = case.create_conversation([&alice, &bob]).await;
        let epoch_before_charlie = conversation.guard().await.epoch().await;

        let conversation = conversation.invite_notify([&charlie]).await;
        let encrypted = conversation
            .guard_of(&charlie)
            .await
            .encrypt_targeted(
                &bob.get_client_id().await,
                TargetedMessagePolicy::Persisted,
                b"charlie claiming to have been here all along".to_vec(),
            )
            .await
            .unwrap();
        let forged = backdate(&encrypted, epoch_before_charlie, &conversation.guard_of(&charlie).await).await;

        let error = conversation
            .guard_of(&bob)
            .await
            .decrypt_message(forged)
            .await
            .unwrap_err();
        assert!(
            matches!(
                error,
                Error::MlsMessageInvalidState("old epoch member data not found for the sender")
            ),
            "a sender with no leaf in the claimed epoch must be rejected, got {error:?}"
        );
    }

    #[apply(all_cred_cipher)]
    async fn transient_targeted_message_from_a_past_epoch_is_rejected(case: TestContext) {
        let [alice, bob] = case.sessions().await;
        let conversation = case.create_conversation([&alice, &bob]).await;

        let encrypted = conversation
            .guard()
            .await
            .encrypt_targeted(
                &bob.get_client_id().await,
                TargetedMessagePolicy::Transient,
                b"only meaningful in the epoch it was sent".to_vec(),
            )
            .await
            .unwrap();

        let conversation = conversation.update_notify().await;

        let error = conversation
            .guard_of(&bob)
            .await
            .decrypt_message(encrypted)
            .await
            .unwrap_err();
        assert!(
            matches!(error, Error::InvalidTransientMessageEpoch { .. }),
            "transient messages must only be decrypted in the epoch they were sent, got {error:?}"
        );
    }

    /// A targeted message can be decrypted from a past epoch which the recipient entered by processing a commit.
    ///
    /// The other past-epoch tests all send in the epoch the recipient joined in, which is recorded when the
    /// conversation is first persisted. This one sends in an epoch that only exists because of a later commit.
    #[apply(all_cred_cipher)]
    async fn targeted_message_from_an_epoch_entered_by_commit_can_be_decrypted_later(case: TestContext) {
        let [alice, bob] = case.sessions().await;
        let conversation = case.create_conversation([&alice, &bob]).await;
        let joined_epoch = conversation.guard_of(&bob).await.epoch().await;

        let conversation = conversation.update_notify().await;
        let sending_epoch = conversation.guard_of(&bob).await.epoch().await;
        assert!(
            sending_epoch > joined_epoch,
            "the test is only meaningful if the message is sent after an epoch change"
        );

        let message = b"sent in an epoch bob entered by commit";
        let encrypted = conversation
            .guard()
            .await
            .encrypt_targeted(
                &bob.get_client_id().await,
                TargetedMessagePolicy::Persisted,
                message.to_vec(),
            )
            .await
            .unwrap();

        let conversation = conversation.update_notify().await;

        let decrypted = conversation
            .guard_of(&bob)
            .await
            .decrypt_message(encrypted)
            .await
            .unwrap()
            .into_persisted_targeted()
            .unwrap();
        assert_eq!(decrypted.plaintext, message);
    }
}
