use super::{ConversationGuard, Result};
use crate::mls::conversation::{ConversationWithMls, Error};
use crate::obfuscate::Obfuscated;
use crate::prelude::MlsConversationDecryptMessage;
use crate::{KeystoreError, RecursiveError};
use core_crypto_keystore::CryptoKeystoreMls as _;
use log::info;
use openmls::framing::MlsMessageIn;
use openmls_traits::OpenMlsCryptoProvider as _;
use tls_codec::Deserialize as _;

impl ConversationGuard {
    /// Deserializes a TLS-serialized message, then deciphers it
    ///
    /// # Arguments
    /// * `conversation` - the group/conversation id
    /// * `message` - the encrypted message as a byte array
    ///
    /// # Return type
    /// This method will return a tuple containing an optional message and an optional delay time
    /// for the callers to wait for committing. A message will be `None` in case the provided payload in
    /// case of a system message, such as Proposals and Commits. Otherwise it will return the message as a
    /// byte array. The delay will be `Some` when the message has a proposal
    ///
    /// # Errors
    /// If the conversation can't be found, an error will be returned. Other errors are originating
    /// from OpenMls and the KeyStore
    pub async fn decrypt_message(&mut self, message: impl AsRef<[u8]>) -> Result<MlsConversationDecryptMessage> {
        let mls_message_in =
            MlsMessageIn::tls_deserialize(&mut message.as_ref()).map_err(Error::tls_deserialize("mls message in"))?;
        let client = self.mls_client().await?;
        let backend = &self.mls_provider().await?;
        let parent = self.get_parent().await?;
        let mut conversation = self.conversation_mut().await;
        let decrypt_message_result = conversation
            .decrypt_message(mls_message_in, parent.as_ref(), &client, backend, true)
            .await;
        drop(conversation);

        let conversation = self.conversation().await;
        let context = &self.central_context;
        if let Err(Error::BufferedFutureMessage { message_epoch }) = decrypt_message_result {
            context
                .handle_future_message(conversation.id(), message.as_ref())
                .await?;
            info!(group_id = Obfuscated::from(conversation.id()); "Buffered future message from epoch {message_epoch}");
        }

        // In the inner `decrypt_message` above, we raise the `BufferedCommit` error, but we only handle it here.
        // That's because in that scope we don't have access to the raw message bytes; here, we do.
        if let Err(Error::BufferedCommit) = decrypt_message_result {
            conversation.buffer_pending_commit(backend, message).await?;
        }

        let decrypt_message = decrypt_message_result?;

        if !decrypt_message.is_active {
            // drop conversation to allow borrowing `self` again
            drop(conversation);
            self.wipe().await?;
        }
        Ok(decrypt_message)
    }

    /// Destroys a group locally
    ///
    /// # Errors
    /// KeyStore errors, such as IO
    pub async fn wipe(&mut self) -> Result<()> {
        let provider = self.mls_provider().await?;
        let mut group_store = self
            .central_context
            .mls_groups()
            .await
            .map_err(RecursiveError::root("getting mls groups"))?;
        let mut conversation = self.conversation_mut().await;
        conversation.wipe_associated_entities(&provider).await?;
        provider
            .key_store()
            .mls_group_delete(conversation.id())
            .await
            .map_err(KeystoreError::wrap("deleting mls group"))?;
        let _ = group_store.remove(conversation.id());
        Ok(())
    }
}
