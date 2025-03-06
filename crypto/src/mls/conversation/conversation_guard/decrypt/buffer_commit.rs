use super::ConversationWithMls as _;
use super::Result;
use super::{ConversationGuard, RecursionPolicy};
use crate::KeystoreError;
use crate::mls::conversation::Error;
use crate::obfuscate::Obfuscated;
use crate::prelude::MlsConversationDecryptMessage;
use core_crypto_keystore::connection::FetchFromDatabase as _;
use core_crypto_keystore::entities::MlsBufferedCommit;
use log::info;
use openmls::framing::MlsMessageIn;
use openmls_traits::OpenMlsCryptoProvider as _;
use tls_codec::Deserialize as _;

impl ConversationGuard {
    /// Cache the bytes of a buffered commit in the backend.
    ///
    /// By storing the raw commit bytes and doing deserialization/decryption from scratch, we preserve all
    /// security guarantees. When we do restore, it's as though the commit had simply been received later.
    pub(super) async fn buffer_commit(&self, commit: impl AsRef<[u8]>) -> Result<()> {
        let conversation = self.conversation().await;
        info!(group_id = Obfuscated::from(conversation.id()); "buffering commit");

        let buffered_commit = MlsBufferedCommit::new(conversation.id().clone(), commit.as_ref().to_owned());

        self.mls_provider()
            .await?
            .key_store()
            .save(buffered_commit)
            .await
            .map_err(KeystoreError::wrap("buffering commit"))?;
        Ok(())
    }

    /// Retrieve the bytes of a pending commit.
    pub(super) async fn retrieve_buffered_commit(&self) -> Result<Option<Vec<u8>>> {
        let conversation = self.conversation().await;
        info!(group_id = Obfuscated::from(conversation.id()); "attempting to retrieve buffered commit");
        self.mls_provider()
            .await?
            .keystore()
            .find::<MlsBufferedCommit>(conversation.id())
            .await
            .map(|option| option.map(MlsBufferedCommit::into_commit_data))
            .map_err(KeystoreError::wrap("attempting to retrieve buffered commit"))
            .map_err(Into::into)
    }

    /// Try to apply a buffered commit.
    ///
    /// This is largely a convenience function which handles deserializing the message, and
    /// gives a convenient point around which we can add context to errors. However, it's also
    /// a place where we can introduce a pin, given that we're otherwise doing a recursive
    /// async call, which would result in an infinitely-sized future.
    pub(super) async fn try_process_buffered_commit(
        &mut self,
        commit: impl AsRef<[u8]>,
        recursion_policy: RecursionPolicy,
    ) -> Result<MlsConversationDecryptMessage> {
        let conversation = self.conversation().await;
        info!(group_id = Obfuscated::from(conversation.id()); "attempting to process buffered commit");
        drop(conversation);

        let message =
            MlsMessageIn::tls_deserialize(&mut commit.as_ref()).map_err(Error::tls_deserialize("mls message in"))?;

        Box::pin(self.decrypt_message_inner(message, recursion_policy)).await
    }

    /// Remove the buffered commit for this conversation; it has been applied.
    pub(super) async fn clear_buffered_commit(&self) -> Result<()> {
        let conversation = self.conversation().await;
        info!(group_id = Obfuscated::from(conversation.id()); "attempting to delete buffered commit");
        self.mls_provider()
            .await?
            .keystore()
            .remove::<MlsBufferedCommit, _>(conversation.id())
            .await
            .map_err(KeystoreError::wrap("attempting to clear buffered commit"))
            .map_err(Into::into)
    }
}
