use core_crypto_keystore::{
    entities::{MessageRxCounterPkRef, TransientMessageRxCounter},
    traits::FetchFromDatabase as _,
};
use openmls::prelude::{Member, OpenMlsCrypto};
use openmls_traits::OpenMlsCryptoProvider;
use tls_codec::{Deserialize as _, Serialize, VLBytes};

use super::{Error, Result};
use crate::{
    DecryptedMessage, KeystoreError, OpenMlsError, RecursiveError, TlsCodecError,
    mls::conversation::{
        ConversationMut,
        mutable::tnt::{ProtocolVersion, TransientMessage, transient::transient_message_secrets},
    },
};

impl ConversationMut {
    pub(in crate::mls::conversation::mutable::tnt) async fn decrypt_transient(
        &self,
        message: TransientMessage,
        protocol_version: ProtocolVersion,
        sender: &Member,
    ) -> Result<DecryptedMessage> {
        let mls_group = self.group().await;
        let message_epoch = message.epoch().as_u64();
        let group_epoch = mls_group.epoch().as_u64();
        if message_epoch != group_epoch {
            return Err(Error::InvalidTransientMessageEpoch {
                group_epoch,
                message_epoch,
            });
        }

        let database = self.database().await?;
        let counter_pk = MessageRxCounterPkRef::new(self.id.as_ref().into(), message.sender.u32(), group_epoch);

        let existing_counter = database
            .get_borrowed::<TransientMessageRxCounter>(counter_pk)
            .await
            .map_err(KeystoreError::wrap("getting TransientMessageRxCounter"))?
            .map(|counter| counter.count)
            .unwrap_or_default();
        if u32::from(message.counter) <= existing_counter {
            return Err(Error::DuplicateMessage);
        }

        let crypto_provider = self.crypto_provider().await?;
        let cipher_suite = self.cipher_suite();
        let aad = message.aad(protocol_version);
        let secrets = transient_message_secrets(&crypto_provider, &aad, &mls_group)?;
        let aad_bytes = message
            .aad(protocol_version)
            .tls_serialize_detached()
            .map_err(TlsCodecError::serialize("TransientMessageAad"))?;
        let padded_plaintext = crypto_provider
            .crypto()
            .aead_decrypt(
                cipher_suite.aead_algorithm(),
                &secrets.secret_key,
                &message.payload,
                secrets.aead_nonce.as_slice(),
                &aad_bytes,
            )
            .map_err(OpenMlsError::wrap("decrypting transient message"))?;

        // Remove padding from plaintext: VLBytes contains a length prefix which tells the deserializer the plaintext
        // length.
        let plaintext = VLBytes::tls_deserialize(&mut padded_plaintext.as_slice())
            .map_err(TlsCodecError::deserialize("TargetedMessageContent"))?
            .into();

        let tx = self
            .tx_context
            .inner()
            .await
            .map_err(RecursiveError::transaction("getting inner context"))?;
        let tx = tx.transaction();
        tx.save(TransientMessageRxCounter {
            conversation_id: self.id().into(),
            sender: message.sender.u32(),
            epoch: group_epoch,
            count: message.counter.into(),
        })
        .await
        .map_err(KeystoreError::wrap("persisting TransientMessageRxCounter"))?;

        let decrypted_bytes = self.extract_sender_id(sender, plaintext).await?;

        Ok(DecryptedMessage::Transient(decrypted_bytes))
    }
}
