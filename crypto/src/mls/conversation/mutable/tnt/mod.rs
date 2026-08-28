mod targeted;
mod tnt_message_counter;
mod transient;

use core_crypto_keystore::{
    entities::{MessageRxCounterPkRef, TargetedMessageRxCounter, TransientMessageRxCounter},
    traits::FetchFromDatabase,
};
use openmls::prelude::{
    CredentialWithKey, LeafNodeIndex, Member, OpenMlsSignaturePublicKey, Signable as _, Signature, Verifiable as _,
};
use openmls_traits::OpenMlsCryptoProvider;
use tls_codec::{Serialize, TlsDeserialize, TlsSerialize, TlsSize, VLBytes};

use self::targeted::TargetedMessage;
pub use self::targeted::encrypt::TargetedMessagePolicy;
pub(crate) use self::tnt_message_counter::TntMessageCounter;
use super::Result;
use crate::{
    ConversationConfiguration, DecryptedBytes, DecryptedMessage, KeystoreError, OpenMlsError, RecursiveError,
    TlsCodecError,
    mls::{
        conversation::{ConversationMut, Error, mutable::tnt::transient::TransientMessage},
        credential::ext::CredentialExt as _,
    },
};

const PADDING_SIZE: usize = ConversationConfiguration::PADDING_SIZE;

/// The version of the Transient and Targeted Messages protocol.
#[derive(Clone, Copy, PartialEq, Eq, TlsSize, TlsSerialize, TlsDeserialize)]
#[repr(transparent)]
struct ProtocolVersion(u16);

impl ProtocolVersion {
    /// Transient and Targeted Messages Version 1
    const V1: Self = Self(1);

    const CURRENT: Self = Self::V1;

    const fn as_u16(&self) -> u16 {
        self.0
    }
}

/// The body of [TntMessageTBS], with currently three variants. The wire format is encoded in the leading two
/// bytes of the TLS-serialized version of this struct. The wire-format values are contained in the range reserved for
/// private use in RFC 9420.
#[derive(TlsSize, TlsSerialize, TlsDeserialize)]
#[repr(u16)]
#[non_exhaustive]
enum TntMessageBody {
    /// A transient message.
    #[tls_codec(discriminant = 0xF000)]
    Transient(TransientMessage),
    /// A targeted message.
    #[tls_codec(discriminant = 0xF001)]
    Targeted(TargetedMessage),
    /// A transient, targeted message.
    #[tls_codec(discriminant = 0xF002)]
    TransientTargeted(TargetedMessage),
}

#[derive(TlsSize, TlsDeserialize, TlsSerialize, derive_more::From, PartialEq, Eq)]
pub(crate) struct TntWireFormat(u16);

impl TntWireFormat {
    pub(crate) const TRANSIENT_MESSAGE: Self = Self(0xF000);

    pub(crate) const TARGETED_MESSAGE: Self = Self(0xF001);
    pub(crate) const TRANSIENT_TARGETED_MESSAGE: Self = Self(0xF002);

    pub(crate) const MIN: u16 = Self::TRANSIENT_MESSAGE.0;
    pub(crate) const MAX: u16 = Self::TRANSIENT_TARGETED_MESSAGE.0;

    pub(crate) const ALL: std::ops::RangeInclusive<u16> = Self::MIN..=Self::MAX;

    /// The total received count of the given message type from the given sender, conversation, and epoch.
    ///
    /// Implementation note: because transient targeted message and targeted message share a type, we're implementing
    /// this here instead of the types themselves.
    async fn total_received_message_count(
        &self,
        database: &impl FetchFromDatabase,
        primary_key: MessageRxCounterPkRef<'_>,
    ) -> Result<u32> {
        let count = match *self {
            Self::TRANSIENT_MESSAGE => database
                .get_borrowed::<TransientMessageRxCounter>(primary_key)
                .await
                .map_err(KeystoreError::wrap("getting TransientMessageRxCounter"))?
                .map(|counter| counter.count)
                .unwrap_or_default(),
            Self::TRANSIENT_TARGETED_MESSAGE => database
                .get_borrowed::<TransientMessageRxCounter>(primary_key)
                .await
                .map_err(KeystoreError::wrap("getting TransientMessageRxCounter"))?
                .map(|counter| counter.count)
                .unwrap_or_default(),
            Self::TARGETED_MESSAGE => database
                .get_borrowed::<TargetedMessageRxCounter>(primary_key)
                .await
                .map_err(KeystoreError::wrap("getting TargetedMessageRxCounter"))?
                .map(|counter| counter.count)
                .unwrap_or_default(),

            _ => panic!("All TntWireFormats map to a MessageRxCounter implementation"),
        };

        Ok(count)
    }
}

/// The to-be-signed [TntMessage].
#[derive(TlsSize, TlsSerialize, TlsDeserialize)]
struct TntMessageTBS {
    protocol_version: ProtocolVersion,
    body: TntMessageBody,
}

impl TntMessageTBS {
    fn new_transient(transient: TransientMessage) -> Self {
        Self {
            protocol_version: ProtocolVersion::CURRENT,
            body: TntMessageBody::Transient(transient),
        }
    }

    fn new_targeted(targeted: TargetedMessage) -> Self {
        Self {
            protocol_version: ProtocolVersion::CURRENT,
            body: TntMessageBody::Targeted(targeted),
        }
    }

    fn new_transient_targeted(targeted: TargetedMessage) -> Self {
        Self {
            protocol_version: ProtocolVersion::CURRENT,
            body: TntMessageBody::TransientTargeted(targeted),
        }
    }

    pub(super) fn sender_index(&self) -> LeafNodeIndex {
        match &self.body {
            TntMessageBody::Transient(transient_message) => transient_message.sender(),
            TntMessageBody::Targeted(targeted_message) | TntMessageBody::TransientTargeted(targeted_message) => {
                targeted_message.sender()
            }
        }
    }
}

/// A message containing [TntMessageBody] with the corresponding signature.
#[derive(TlsSize, TlsSerialize, TlsDeserialize)]
pub(super) struct TntMessage {
    content: TntMessageTBS,
    signature: Signature,
}

impl openmls::prelude::Signable for TntMessageTBS {
    type SignedOutput = TntMessage;

    fn unsigned_payload(&self) -> Result<Vec<u8>, tls_codec::Error> {
        self.tls_serialize_detached()
    }

    fn label(&self) -> &str {
        match self.body {
            TntMessageBody::Transient(_) => TransientMessage::SIGN_LABEL,
            TntMessageBody::Targeted(_) => TargetedMessage::SIGN_LABEL_PERSISTED,
            TntMessageBody::TransientTargeted(_) => TargetedMessage::SIGN_LABEL_TRANSIENT,
        }
    }
}

impl openmls::prelude::SignedStruct<TntMessageTBS> for TntMessage {
    fn from_payload(payload: TntMessageTBS, signature: openmls::prelude::Signature) -> Self {
        Self {
            content: payload,
            signature,
        }
    }
}

impl openmls::prelude::Verifiable for TntMessage {
    fn unsigned_payload(&self) -> Result<Vec<u8>, tls_codec::Error> {
        self.content.tls_serialize_detached()
    }

    fn signature(&self) -> &Signature {
        &self.signature
    }

    fn label(&self) -> &str {
        match self.content.body {
            TntMessageBody::Transient(_) => TransientMessage::SIGN_LABEL,
            TntMessageBody::Targeted(_) => TargetedMessage::SIGN_LABEL_PERSISTED,
            TntMessageBody::TransientTargeted(_) => TargetedMessage::SIGN_LABEL_TRANSIENT,
        }
    }
}

impl ConversationMut {
    /// Verify the [TntMessage] signature, then proceed with decryption.
    pub(super) async fn decrypt_tnt_message(&self, message: TntMessage) -> Result<DecryptedMessage> {
        let protocol_version = message.content.protocol_version;
        // Currently, we only support `ProtocolVersion::V1`, so we're throwing an error if anyone from a future version
        // sends us a message.
        if protocol_version != ProtocolVersion::V1 {
            return Err(Error::MlsMessageInvalidState("Unsupported tnt protocol version"));
        }

        let crypto_provider = self.crypto_provider().await?;
        let signature_algorithm = self.cipher_suite().signature_algorithm();
        let sender = self
            .group()
            .await
            .members()
            .find(|member| member.index == message.content.sender_index())
            .ok_or(Error::MlsMessageInvalidState("tnt sender is not a group member"))?;

        let sender_public_key =
            OpenMlsSignaturePublicKey::new(sender.signature_key.clone().into(), signature_algorithm)
                .map_err(OpenMlsError::wrap("constructing tnt sender signature key"))?;
        message
            .verify_no_out(crypto_provider.crypto(), &sender_public_key)
            .map_err(OpenMlsError::wrap("verifying tnt message signature"))?;

        match message.content.body {
            TntMessageBody::Transient(transient_message) => {
                self.decrypt_transient(transient_message, protocol_version, &sender)
                    .await
            }
            TntMessageBody::Targeted(targeted_message) => {
                self.decrypt_targeted(
                    targeted_message,
                    TargetedMessagePolicy::Persisted,
                    protocol_version,
                    &sender,
                )
                .await
            }
            TntMessageBody::TransientTargeted(targeted_message) => {
                self.decrypt_targeted(
                    targeted_message,
                    TargetedMessagePolicy::Transient,
                    protocol_version,
                    &sender,
                )
                .await
            }
        }
    }

    /// The final steps of each tnt message encryption procedure: sign, format as [TntMessage] and serialize.
    async fn sign_tnt_message(&self, tbs: TntMessageTBS) -> Result<Vec<u8>> {
        let credential = self.find_current_credential().await?;
        let signature_key = credential.signature_key();
        let signed_message: TntMessage = tbs
            .sign(signature_key)
            .map_err(OpenMlsError::wrap("signing TntMessageTBS"))?;

        signed_message
            .tls_serialize_detached()
            .map_err(TlsCodecError::serialize("TntMessage"))
            .map_err(Into::into)
    }

    /// Shared function for all tnt message types, parameterized by message type and sender, because that's how the
    /// receiver counters are split.
    /// The additional complexity introduced by this split is worthwhile, because each message type may be delivered in
    /// a unique way. We don't want to assume that messages arrive in order across different message types. This is why
    /// we're just checking the counter of the same message type, which is enough for duplicate message detection.
    async fn ensure_no_duplicate_message(
        &self,
        group_epoch: u64,
        message_type: TntWireFormat,
        message_sender: LeafNodeIndex,
        message_counter: TntMessageCounter,
    ) -> Result<()> {
        let database = self.database().await?;
        let counter_pk = MessageRxCounterPkRef::new(self.id.as_ref(), message_sender.u32(), group_epoch);
        let existing_counter = message_type
            .total_received_message_count(database.as_ref(), counter_pk)
            .await?;

        if u32::from(message_counter) > existing_counter {
            Ok(())
        } else {
            Err(Error::DuplicateMessage)
        }
    }

    /// The final step after decrypting a tnt message: extract the sender client id and format as [DecryptedBytes].
    async fn extract_sender_id(&self, sender: &Member, plaintext: Vec<u8>) -> Result<DecryptedBytes> {
        let crypto_provider = self.crypto_provider().await?;
        let sender_credential_with_key = CredentialWithKey {
            credential: sender.credential.clone(),
            signature_key: sender.signature_key.clone().into(),
        };
        let pki_env = crypto_provider.authentication_service().pki_env().await;
        let identity = sender_credential_with_key
            .extract_identity(self.cipher_suite(), pki_env.as_deref())
            .await
            .map_err(RecursiveError::mls_credential("extracting identity"))?;
        let sender_client_id = sender
            .credential
            .identity()
            .try_into()
            .map_err(RecursiveError::mls_client("client id from credential"))?;
        let decrypted_bytes = DecryptedBytes {
            plaintext,
            sender_client_id,
            identity,
        };
        Ok(decrypted_bytes)
    }
}

/// Used for plaintext padding before encrypting tnt messages.
fn tls_serialize_padded(message: &[u8]) -> Result<Vec<u8>, tls_codec::Error> {
    // VLBytes includes a length prefix, so whoever decrypts the ciphertext will know the payload length.
    let mut payload = VLBytes::from(message).tls_serialize_detached()?;
    payload.resize(payload.len().next_multiple_of(PADDING_SIZE), 0);
    Ok(payload)
}
