use core_crypto_keystore::Database;
use openmls::prelude::OpenMlsCrypto;
use tls_codec::Serialize as _;

use crate::{
    CryptoProvider, OpenMlsError, RecursiveError, TlsCodecError,
    mls::conversation::{
        ConversationMut, MlsGroupState, Result,
        mutable::tnt::{
            TntMessageTBS, TransientMessage, tls_serialize_padded,
            transient::{TransientMessageAad, transient_message_secrets},
        },
    },
};

impl ConversationMut {
    /// Transient messages are messages distributed to clients with an active WebSocket connection. They don't mutate
    /// regular group state (i.e., as defined by RFC 9420). That is because offline clients will never receive those
    /// messages, and will not have the appropriate cryptographic state to decrypt the messages.
    ///
    /// Any feature using a targeted, transient or transient targeted message MUST specify why the lower security
    /// guarantees (compared to MLS application messages) are acceptable and/or how they are mitigated.
    pub async fn encrypt_transient(&mut self, message: Vec<u8>) -> Result<Vec<u8>> {
        let crypto_provider = self
            .tx_context
            .crypto_provider()
            .await
            .map_err(RecursiveError::transaction("obtaining crypto provider"))?;
        let database = self.database().await?;

        let transient_message = self
            .mutate_group(async |_, group_state, _| {
                Self::create_transient_message(&database, group_state, &crypto_provider, &message).await
            })
            .await?;

        let tbs = TntMessageTBS::new_transient(transient_message);
        self.sign_tnt_message(tbs).await
    }

    async fn create_transient_message(
        database: &Database,
        group_state: &mut MlsGroupState,
        crypto_provider: &CryptoProvider,
        message: &[u8],
    ) -> Result<TransientMessage> {
        let counter = group_state.obtain_transient_message_tx_counter(database).await?;
        let mls_group = group_state.mls_group();
        let aad = TransientMessageAad::new(mls_group.own_leaf_index(), counter, mls_group.export_group_context());

        let secrets = transient_message_secrets(crypto_provider, &aad, mls_group)?;
        let message = tls_serialize_padded(message).map_err(TlsCodecError::serialize("transient message content"))?;
        let cipher_suite = mls_group.ciphersuite();
        let aad = aad
            .tls_serialize_detached()
            .map_err(TlsCodecError::serialize("TransientMessageAad"))?;
        let payload = crypto_provider
            .aead_encrypt(
                cipher_suite.aead_algorithm(),
                &secrets.secret_key,
                &message,
                secrets.aead_nonce.as_slice(),
                &aad,
            )
            .map_err(OpenMlsError::wrap("encrypting transient message"))?;

        let sender = mls_group.own_leaf_index();
        let group_context = mls_group.export_group_context().clone();

        let transient_message = TransientMessage::new(sender, counter, group_context, payload);
        Ok(transient_message)
    }
}
