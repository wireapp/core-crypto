mod decrypt;
mod encrypt;

use const_format::concatcp;
use openmls::{
    group::{GroupEpoch, MlsGroup, group_context::GroupContext},
    prelude::{LeafNodeIndex, OpenMlsCrypto as _},
};
use openmls_traits::OpenMlsCryptoProvider;
use tls_codec::{SecretVLBytes, Serialize as _, TlsDeserialize, TlsSerialize, TlsSize};

use super::{Error, Result};
use crate::{
    OpenMlsError, TlsCodecError,
    mls::{
        TntMessageCounter,
        conversation::mutable::tnt::{ProtocolVersion, TntWireFormat},
    },
};

/// Used as aad for AEAD.
#[derive(TlsSize, TlsDeserialize, TlsSerialize)]
struct TransientMessageAad {
    protocol_version: ProtocolVersion,
    wire_format: TntWireFormat,
    sender: LeafNodeIndex,
    counter: TntMessageCounter,
    /// The mls group context ([https://www.rfc-editor.org/info/rfc9420/#name-group-context]) contains the epoch and
    /// group id, so we don't need those in additional fields here.
    group_context: GroupContext,
}

impl TransientMessageAad {
    fn new(sender: LeafNodeIndex, counter: TntMessageCounter, group_context: &GroupContext) -> Self {
        Self {
            protocol_version: ProtocolVersion::CURRENT,
            wire_format: TntWireFormat::TRANSIENT_MESSAGE,
            sender,
            counter,
            group_context: group_context.clone(),
        }
    }
}

/// Transient messages are messages distributed to clients with an active WebSocket connection. They don't mutate
/// regular group state (i.e., as defined by RFC 9420). That is because offline clients will never receive those
/// messages, and will not have the appropriate cryptographic state to decrypt the messages.
///
/// Any feature using a targeted, transient or transient targeted message MUST specify why the lower security guarantees
/// (compared to MLS application messages) are acceptable and/or how they are mitigated.
///
/// Implementation note: we're preferring OpenMLS types here, because we're using OpenMLS encoding. Once we switch to
/// mls-rs, we're going to use mls-rs types.
#[derive(TlsSize, TlsSerialize, TlsDeserialize, derive_more::Constructor)]
pub(super) struct TransientMessage {
    sender: LeafNodeIndex,
    counter: TntMessageCounter,
    /// The mls group context ([https://www.rfc-editor.org/info/rfc9420/#name-group-context]) contains the epoch and
    /// group id, so we don't need those in additional fields here.
    group_context: GroupContext,
    /// AEAD-encrypted with an MLS exporter secret. An additional authentication layer is
    /// provided by the signature over the entire message. Before encryption, the plaintext is padded.
    payload: Vec<u8>,
}

impl TransientMessage {
    pub(super) const SIGN_LABEL: &str = concatcp!("TntMessageTBS-Transient v", ProtocolVersion::CURRENT.as_u16());
    pub(super) const AEAD_SECRET_KEY_LABEL: &str =
        concatcp!("Tnt TransientMessage Secret Key v", ProtocolVersion::CURRENT.as_u16());
    pub(super) const AEAD_NONCE_SECRET_LABEL: &str =
        concatcp!("Tnt TransientMessage Nonce Secret v", ProtocolVersion::CURRENT.as_u16());

    fn aad(&self, protocol_version: ProtocolVersion) -> TransientMessageAad {
        TransientMessageAad {
            protocol_version,
            wire_format: TntWireFormat::TRANSIENT_MESSAGE,
            sender: self.sender,
            counter: self.counter,
            group_context: self.group_context.clone(),
        }
    }

    fn epoch(&self) -> GroupEpoch {
        self.group_context.epoch()
    }

    pub(super) fn sender(&self) -> LeafNodeIndex {
        self.sender
    }
}

struct TransientMessageSecrets {
    aead_nonce: SecretVLBytes,
    secret_key: zeroize::Zeroizing<Vec<u8>>,
}

fn transient_message_secrets(
    crypto_provider: &impl OpenMlsCryptoProvider,
    aad: &TransientMessageAad,
    mls_group: &MlsGroup,
) -> Result<TransientMessageSecrets> {
    let cipher_suite = mls_group.ciphersuite();

    // Mix both the sender index and the counter into the aead nonce
    let sender_index_bytes = aad
        .sender
        .tls_serialize_detached()
        .map_err(TlsCodecError::serialize("LeafNodeIndex"))?;
    let nonce_secret = mls_group
        .export_secret(
            crypto_provider,
            TransientMessage::AEAD_NONCE_SECRET_LABEL,
            &sender_index_bytes,
            cipher_suite.hash_length(),
        )
        .map_err(OpenMlsError::wrap("exporting aead nonce secret"))?;

    let counter_bytes = aad
        .counter
        .tls_serialize_detached()
        .map_err(TlsCodecError::serialize("TntMessageCounter"))?;
    let aead_nonce = crypto_provider
        .crypto()
        .hkdf_expand(
            cipher_suite.hash_algorithm(),
            &nonce_secret,
            &counter_bytes,
            cipher_suite.aead_nonce_length(),
        )
        .map_err(OpenMlsError::wrap("expanding aead nonce secret to nonce"))?;

    let secret_key = mls_group
        .export_secret(
            crypto_provider,
            TransientMessage::AEAD_SECRET_KEY_LABEL,
            &sender_index_bytes,
            cipher_suite.aead_key_length(),
        )
        .map_err(OpenMlsError::wrap("exporting aead encryption key"))?;

    Ok(TransientMessageSecrets {
        aead_nonce,
        secret_key: secret_key.into(),
    })
}

#[cfg(test)]
mod tests {
    use core_crypto_keystore::entities::TntMessageTxCounter;
    use core_crypto_keystore::traits::FetchFromDatabase as _;

    use crate::mls::conversation::{Conversation, ConversationMut};
    use crate::test_utils::*;

    #[apply(all_cred_cipher)]
    async fn can_decrypt_transient_message(case: TestContext) {
        let [alice, bob] = case.sessions().await;
        let conversation = case.create_conversation([&alice, &bob]).await;

        let message = b"This is a transient message";
        let encrypted = conversation
            .guard()
            .await
            .encrypt_transient(message.to_vec())
            .await
            .unwrap();
        assert_ne!(&message, &encrypted.as_slice());

        let decrypted = conversation
            .guard_of(&bob)
            .await
            .decrypt_message(encrypted)
            .await
            .unwrap()
            .into_transient()
            .unwrap()
            .plaintext;

        assert_eq!(&decrypted, &message);
    }

    #[apply(all_cred_cipher)]
    async fn cant_decrypt_same_transient_message_twice(case: TestContext) {
        let [alice, bob] = case.sessions().await;
        let conversation = case.create_conversation([&alice, &bob]).await;

        let message = b"This is a transient message";
        let encrypted = conversation
            .guard()
            .await
            .encrypt_transient(message.to_vec())
            .await
            .unwrap();
        assert_ne!(&message, &encrypted.as_slice());

        let decrypted = conversation
            .guard_of(&bob)
            .await
            .decrypt_message(&encrypted)
            .await
            .unwrap()
            .into_transient()
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
    async fn unrelated_mutation_after_reload_preserves_tnt_counter(case: TestContext) {
        let [mut alice, bob] = case.sessions().await;
        let conversation = case.create_conversation([&alice, &bob]).await;
        let id = conversation.id().clone();
        let epoch = conversation.guard().await.epoch().await;

        let first = conversation
            .guard()
            .await
            .encrypt_transient(b"first".to_vec())
            .await
            .unwrap();
        conversation.guard_of(&bob).await.decrypt_message(&first).await.unwrap();
        drop(conversation);
        alice.commit_transaction().await;

        // Both loading paths start with a cold in-memory counter. An ordinary MLS encryption
        // persists group state without using that counter or advancing the epoch.
        let session = alice.session().await;
        session.conversation_cache.lock().await.clear();
        let loaded = Conversation::load(session.clone(), id.as_ref()).await.unwrap().unwrap();
        let loaded = session.conversation_cache.lock().await.insert(loaded);
        let mut loaded = ConversationMut::new(loaded, alice.transaction.clone());
        loaded.encrypt_message(b"ordinary MLS message").await.unwrap();
        assert_eq!(loaded.epoch().await, epoch);

        let counter = alice
            .database()
            .get_borrowed::<TntMessageTxCounter>(id.keystore())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            counter.count, 1,
            "persisting unrelated group state must preserve the stored TNT counter"
        );

        let second = loaded.encrypt_transient(b"second".to_vec()).await.unwrap();
        drop(loaded);
        alice.commit_transaction().await;

        let counter = alice
            .database()
            .get_borrowed::<TntMessageTxCounter>(id.keystore())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            counter.count, 2,
            "the next transient message must advance the persisted counter"
        );
        let second = bob
            .transaction
            .conversation(&id)
            .await
            .unwrap()
            .decrypt_message(second)
            .await
            .unwrap();
        assert_eq!(second.into_transient().unwrap().plaintext, b"second");
    }

    #[apply(all_cred_cipher)]
    async fn epoch_change_resets_tnt_counter_after_reload(case: TestContext) {
        let [mut alice, bob] = case.sessions().await;
        let conversation = case.create_conversation([&alice, &bob]).await;
        let id = conversation.id().clone();
        let epoch = conversation.guard().await.epoch().await;

        for message in [b"first", b"other"] {
            let encrypted = conversation
                .guard()
                .await
                .encrypt_transient(message.to_vec())
                .await
                .unwrap();
            conversation
                .guard_of(&bob)
                .await
                .decrypt_message(encrypted)
                .await
                .unwrap();
        }
        drop(conversation);
        alice.commit_transaction().await;
        alice.pretend_crash().await;

        let conversation = TestConversation::new_from_existing(&case, id.clone(), vec![&alice, &bob]).await;
        let conversation = conversation.update_notify().await;
        assert_eq!(conversation.guard().await.epoch().await, epoch + 1);
        let counter = alice
            .database()
            .get_borrowed::<TntMessageTxCounter>(id.keystore())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            counter.count, 0,
            "advancing the epoch must reset the counter, even before it is loaded"
        );

        let encrypted = conversation
            .guard()
            .await
            .encrypt_transient(b"new epoch".to_vec())
            .await
            .unwrap();
        let decrypted = conversation
            .guard_of(&bob)
            .await
            .decrypt_message(encrypted)
            .await
            .unwrap();
        assert_eq!(decrypted.into_transient().unwrap().plaintext, b"new epoch");
        let counter = alice
            .database()
            .get_borrowed::<TntMessageTxCounter>(id.keystore())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(counter.count, 1);
    }
}
