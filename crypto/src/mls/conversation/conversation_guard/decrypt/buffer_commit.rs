use core_crypto_keystore::{entities::StoredBufferedCommit, traits::FetchFromDatabase as _};
use log::info;
use openmls::framing::MlsMessageIn;
use openmls_traits::OpenMlsCryptoProvider as _;
use tls_codec::Deserialize as _;

use super::{ConversationGuard, RecursionPolicy, Result};
use crate::{KeystoreError, MlsDecryptMessage, mls::conversation::Error};

impl ConversationGuard {
    /// Cache the bytes of a buffered commit in the backend.
    ///
    /// By storing the raw commit bytes and doing deserialization/decryption from scratch, we preserve all
    /// security guarantees. When we do restore, it's as though the commit had simply been received later.
    pub(super) async fn buffer_commit(&self, commit: impl AsRef<[u8]>) -> Result<()> {
        info!(group_id = self.id().to_owned(); "buffering commit");

        let buffered_commit = StoredBufferedCommit::new(self.id().to_bytes(), commit.as_ref().to_owned());

        self.crypto_provider()
            .await?
            .key_store()
            .save(buffered_commit)
            .await
            .map_err(KeystoreError::wrap("buffering commit"))?;
        Ok(())
    }

    /// Retrieve the bytes of a pending commit.
    pub(super) async fn retrieve_buffered_commit(&self) -> Result<Option<Vec<u8>>> {
        let database = self.database().await?;
        info!(group_id = self.id().to_owned(); "attempting to retrieve buffered commit");
        database
            .get_borrowed::<StoredBufferedCommit>(self.id().as_ref())
            .await
            .map(|option| option.map(StoredBufferedCommit::into_commit_data))
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
    ) -> Result<MlsDecryptMessage> {
        info!(group_id = self.id().to_owned(); "attempting to process buffered commit");

        let message =
            MlsMessageIn::tls_deserialize(&mut commit.as_ref()).map_err(Error::tls_deserialize("mls message in"))?;

        Box::pin(self.decrypt_message_inner(message, recursion_policy)).await
    }

    /// Remove the buffered commit for this conversation; it has been applied.
    pub(super) async fn clear_buffered_commit(&self) -> Result<()> {
        let database = self.database().await?;
        info!(group_id = self.id().to_owned(); "attempting to delete buffered commit");
        database
            .remove_borrowed::<StoredBufferedCommit>(self.id().as_ref())
            .await
            .map_err(KeystoreError::wrap("attempting to clear buffered commit"))
            .map_err(Into::into)
    }
}
