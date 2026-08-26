use std::borrow::Borrow;

use core_crypto_keystore::Database;
use openmls::prelude::{Ciphersuite, Member, Signable as _};
use tls_codec::{Serialize as _, TlsSerialize, TlsSize, VLBytes};

use super::{TargetedMessage, TargetedMessageContext, extract_hpke_context_data};
use crate::{
    ClientIdRef, CryptoProvider, OpenMlsError, RecursiveError, TlsCodecError,
    mls::conversation::{
        ConversationMut, Error, MlsGroupState, Result,
        mutable::tnt::{TntMessage, TntMessageTBS},
    },
};

/// The policy to encrypt the targeted message with.
#[derive(Debug, Clone, Copy, PartialEq, Eq, TlsSize, TlsSerialize)]
#[repr(u8)]
pub enum TargetedMessagePolicy {
    /// Won't be persisted and will only visible to currently online members who immediately process it.
    Transient,
    /// May be persisted and buffered, will also be delivered and processed by currently offline members.
    Persisted,
}

impl ConversationMut {
    /// Targeted messages are messages distributed to individual clients. They don't mutate regular group state (i.e, as
    /// defined by RFC 9420). That is because many or most clients in a group will never receive those messages, and
    /// will not have the appropriate cryptographic state to decrypt the messages.
    ///
    /// Any feature using a targeted, transient or transient targeted message MUST specify why the lower security
    /// guarantees (compared to MLS application messages) are acceptable and/or how they are mitigated.
    pub async fn encrypt_targeted(
        &mut self,
        recipient: impl Borrow<ClientIdRef>,
        policy: TargetedMessagePolicy,
        message: Vec<u8>,
    ) -> Result<Vec<u8>> {
        let cipher_suite = self.cipher_suite();
        let crypto_provider = self
            .tx_context
            .crypto_provider()
            .await
            .map_err(RecursiveError::transaction("obtaining crypto provider"))?;
        let database = self.database().await?;

        let targeted = self
            .mutate_group(async |_, group_state, _| {
                let recipient = group_state
                    .mls_group()
                    .members()
                    .find(|member| ClientIdRef::new(member.credential.identity()) == recipient.borrow())
                    .ok_or_else(|| Error::MemberNotFound(recipient.borrow().to_owned()))?;
                Self::create_targeted_message(
                    &database,
                    policy,
                    group_state,
                    &cipher_suite,
                    &crypto_provider,
                    &recipient,
                    &message,
                )
                .await
            })
            .await?;

        let tbs = match policy {
            TargetedMessagePolicy::Transient => TntMessageTBS::new_transient_targeted(targeted),
            TargetedMessagePolicy::Persisted => TntMessageTBS::new_targeted(targeted),
        };

        let credential = self.find_current_credential().await?;
        let signature_key = credential.signature_key();
        let signed_message: TntMessage = tbs
            .sign(signature_key)
            .map_err(OpenMlsError::wrap("signing TntMessageTBS"))?;

        signed_message
            .tls_serialize_detached()
            .map_err(TlsCodecError::serialize("TntMessage: targeted"))
            .map_err(Into::into)
    }

    async fn create_targeted_message(
        database: &Database,
        policy: TargetedMessagePolicy,
        group_state: &mut MlsGroupState,
        cipher_suite: &Ciphersuite,
        crypto_provider: &CryptoProvider,
        recipient: &Member,
        message: &[u8],
    ) -> Result<TargetedMessage, Error> {
        let counter = group_state
            .obtain_targeted_message_tx_counter(recipient.index, database)
            .await?;
        let mls_group = group_state.mls_group();
        let aad = counter
            .tls_serialize_detached()
            .map_err(TlsCodecError::serialize("TntMessageCounter"))?;
        let context = TargetedMessageContext::new_with_current_protocol_version(
            policy,
            mls_group.export_group_context(),
            mls_group.own_leaf_index(),
            recipient.index,
        );
        let context_data = extract_hpke_context_data(crypto_provider, &context, mls_group)?;
        let message = tls_serialize_padded(message).map_err(TlsCodecError::serialize("TargetedMessageContent"))?;
        let payload = crypto_provider
            .hpke_seal_psk(
                cipher_suite.hpke_config(),
                &recipient.encryption_key,
                &context_data.info,
                &aad,
                &context_data.psk,
                &context_data.psk_id,
                &message,
            )
            .map_err(OpenMlsError::wrap("encrypting targeted message"))?;

        let sender = mls_group.own_leaf_index();
        let group_id = mls_group.group_id();
        let epoch = mls_group.epoch();

        let targeted = TargetedMessage::new(counter, sender, recipient.index, epoch, group_id.clone(), payload);
        Ok(targeted)
    }
}

fn tls_serialize_padded(message: &[u8]) -> Result<Vec<u8>, tls_codec::Error> {
    // VLBytes includes a length prefix, so whoever decrypts the ciphertext will know the payload length.
    let mut payload = VLBytes::from(message).tls_serialize_detached()?;
    payload.resize(payload.len().next_multiple_of(TargetedMessage::PADDING_SIZE), 0);
    Ok(payload)
}
