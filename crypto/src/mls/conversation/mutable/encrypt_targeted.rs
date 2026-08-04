use std::borrow::Borrow;

use openmls::{
    group::MlsGroup,
    prelude::{Member, Signable as _},
};
use tls_codec::{Serialize as _, VLBytes};

use crate::{
    ClientIdRef, OpenMlsError, RecursiveError,
    mls::{
        CoreCryptoMessage, SenderNonce, TargetedMessage,
        conversation::{Error, Result},
        core_crypto_message::{CoreCryptoMessageTBS, PskId, TargetedMessageContext},
    },
};

/// The policy to encrypt the targeted message with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetedMessagePolicy {
    /// Won't be persisted and will only visible to currently online members who immediately process it.
    Transient,
    /// May be persisted and buffered, will also be delivered and processed by currently offline members.
    Persisted,
}

impl super::ConversationMut {
    /// Targeted messages are messages distributed to individual clients. They cannot mutate group state because many or
    /// most clients in a group will never receive those messages, and will not have the appropriate cryptographic state
    /// to decrypt the messages.
    ///
    /// Any feature using a targeted, transient or transient targeted message MUST specify why the compared to MLS
    /// application messages lower guarantees are acceptable and/or how they are mitigated.
    pub async fn encrypt_targeted(
        &mut self,
        recipient: impl Borrow<ClientIdRef>,
        policy: TargetedMessagePolicy,
        message: Vec<u8>,
    ) -> Result<Vec<u8>> {
        let nonce = self
            .mutate_group_and_sender_nonce(async |_, group, _| {
                group.increment_sender_nonce();
                Ok(group.sender_nonce())
            })
            .await?;

        let mls_group_guard = self.group().await;
        let mls_group = mls_group_guard.mls_group();

        let recipient = self.client_id_member(recipient).await?;

        let targeted = self
            .create_targeted_message(mls_group, nonce, recipient, message)
            .await?;

        let tbs = match policy {
            TargetedMessagePolicy::Transient => CoreCryptoMessageTBS::new_transient_targeted(targeted),
            TargetedMessagePolicy::Persisted => CoreCryptoMessageTBS::new_targeted(targeted),
        };

        let credential = self.find_current_credential().await?;
        let signature_key = credential.signature_key();
        let signed_message: CoreCryptoMessage = tbs
            .sign(signature_key)
            .map_err(OpenMlsError::wrap("signing CoreCryptoMessageTBS"))?;

        #[cfg(debug_assertions)]
        {
            use crate::mls::CoreCryptoMessageBody;
            match signed_message.body() {
                CoreCryptoMessageBody::Transient(_) => {
                    panic!("Cannot produce a transient message body in `encrypt_targeted()`")
                }
                CoreCryptoMessageBody::Targeted(_) => {
                    assert!(policy == TargetedMessagePolicy::Persisted)
                }
                CoreCryptoMessageBody::TransientTargeted(_) => {
                    assert!(policy == TargetedMessagePolicy::Transient)
                }
            }
        }

        signed_message
            .tls_serialize_detached()
            .map_err(Error::tls_serialize("CoreCryptoMessage: targeted"))
    }

    async fn create_targeted_message(
        &self,
        mls_group: &MlsGroup,
        nonce: SenderNonce,
        recipient: Member,
        message: Vec<u8>,
    ) -> Result<TargetedMessage, Error> {
        let cipher_suite = self.cipher_suite();
        let aad = nonce
            .tls_serialize_detached()
            .map_err(Error::tls_serialize("SenderNonce"))?;
        let context = TargetedMessageContext::new(mls_group.export_group_context());
        let info = context
            .tls_serialize_detached()
            .map_err(Error::tls_serialize("TargetedMessagaeContext"))?;

        let crypto_provider = &self
            .tx_context
            .crypto_provider()
            .await
            .map_err(RecursiveError::transaction("getting crypto provider"))?;

        // We can use an empty context because we're using a unique label.
        let psk = mls_group
            .export_secret(
                crypto_provider,
                TargetedMessage::PSK_LABEL,
                &[],
                cipher_suite.hash_length(),
            )
            .map_err(OpenMlsError::wrap("exporting targeted message psk"))?;
        let psk_id = PskId::new(mls_group.group_id().clone(), mls_group.epoch());
        let psk_id = psk_id.tls_serialize_detached().map_err(Error::tls_serialize("PskId"))?;
        let message = tls_serialize_padded(message).map_err(Error::tls_serialize("TargetedMessageContent"))?;
        let payload = crypto_provider
            .hpke_seal_psk(
                cipher_suite.hpke_config(),
                &recipient.encryption_key,
                &info,
                &aad,
                &psk,
                &psk_id,
                &message,
            )
            .map_err(OpenMlsError::wrap("encrypting targeted message"))?;

        let sender = mls_group.own_leaf_index();
        let group_id = mls_group.group_id();
        let epoch = mls_group.epoch();

        let targeted = TargetedMessage::new(nonce, sender, recipient.index, epoch, group_id.clone(), payload);
        Ok(targeted)
    }
}

fn tls_serialize_padded(message: Vec<u8>) -> Result<Vec<u8>, tls_codec::Error> {
    // VLBytes includes a length prefix, so whoever decrypts the ciphertext will know the payload length.
    let mut payload = VLBytes::from(message).tls_serialize_detached()?;
    payload.resize(payload.len().next_multiple_of(TargetedMessage::PADDING_SIZE), 0);
    Ok(payload)
}
