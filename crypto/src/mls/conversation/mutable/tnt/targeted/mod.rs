mod decrypt;
pub(super) mod encrypt;

use const_format::concatcp;
use derive_more::Constructor;
use openmls::{
    group::{GroupEpoch, GroupId, MlsGroup, group_context::GroupContext},
    prelude::{Ciphersuite, HpkeCiphertext, LeafNodeIndex},
};
use openmls_traits::OpenMlsCryptoProvider;
use tls_codec::{Serialize as _, TlsDeserialize, TlsSerialize, TlsSize};

use self::encrypt::TargetedMessagePolicy;
use super::{ProtocolVersion, Result, tnt_message_counter::TntMessageCounter};
use crate::{ConversationConfiguration, OpenMlsError, TlsCodecError};

/// Used to parameterize HPKE Seal/Open.
/// Not carried with the payload, constructed freshly when decrypting.
#[derive(TlsSize, TlsSerialize)]
pub(super) struct TargetedMessageContext {
    protocol_version: ProtocolVersion,
    policy: TargetedMessagePolicy,
    sender: LeafNodeIndex,
    recipient: LeafNodeIndex,
    group_context: GroupContext,
}

impl TargetedMessageContext {
    fn new(
        policy: TargetedMessagePolicy,
        group_context: &GroupContext,
        sender: LeafNodeIndex,
        recipient: LeafNodeIndex,
    ) -> Self {
        Self {
            policy,
            protocol_version: ProtocolVersion::V1,
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
    nonce: TntMessageCounter,
    sender: LeafNodeIndex,
    recipient: LeafNodeIndex,
    epoch: GroupEpoch,
    group_id: GroupId,
    /// Encrypted with the receipient's HPKE public key; authenticated with a PSK derived from the epoch secret,
    /// guaranteeing that the sender was a member of the group during the epoch. An additional authentication layer is
    /// provided by the signature over the entire message. Before encryption, the HPKE plaintext is padded.
    payload: HpkeCiphertext,
}

impl TargetedMessage {
    pub(super) const PADDING_SIZE: usize = ConversationConfiguration::PADDING_SIZE;
    pub(super) const SIGN_LABEL_PERSISTED: &str =
        concatcp!("TntMessageTBS-Persisted-Targeted v", ProtocolVersion::V1.as_u16());
    pub(super) const SIGN_LABEL_TRANSIENT: &str =
        concatcp!("TntMessageTBS-Transient-Targeted v", ProtocolVersion::V1.as_u16());
    pub(super) const PSK_LABEL: &str = concatcp!("Tnt TargetedMessage Psk v", ProtocolVersion::V1.as_u16());

    pub(super) fn sender(&self) -> LeafNodeIndex {
        self.sender
    }
}

/// The data that is extracted from the MLS group when encrypting or decrypting a targeted message.
struct HpkeContextData {
    info: Vec<u8>,
    psk_id: Vec<u8>,
    psk: Vec<u8>,
}

fn extract_hpke_context_data(
    crypto_provider: &impl OpenMlsCryptoProvider,
    cipher_suite: &Ciphersuite,
    context: &TargetedMessageContext,
    mls_group: &MlsGroup,
) -> Result<HpkeContextData> {
    let info = context
        .tls_serialize_detached()
        .map_err(TlsCodecError::serialize("TargetedMessageContext"))?;

    let psk = derive_targeted_message_psk(crypto_provider, cipher_suite, mls_group)?;
    let psk_id = PskId::new(mls_group.group_id().clone(), mls_group.epoch());
    let psk_id = psk_id
        .tls_serialize_detached()
        .map_err(TlsCodecError::serialize("PskId"))?;

    Ok(HpkeContextData { info, psk_id, psk })
}

fn derive_targeted_message_psk(
    crypto_provider: &impl OpenMlsCryptoProvider,
    cipher_suite: &Ciphersuite,
    mls_group: &MlsGroup,
) -> Result<Vec<u8>> {
    // We can use an empty context because we're using a unique label.
    mls_group
        .export_secret(
            crypto_provider,
            TargetedMessage::PSK_LABEL,
            &[],
            cipher_suite.hash_length(),
        )
        .map_err(OpenMlsError::wrap("exporting targeted message psk"))
        .map_err(Into::into)
}

#[cfg(test)]
mod tests {
    use super::TargetedMessagePolicy;
    use crate::test_utils::*;

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
}
