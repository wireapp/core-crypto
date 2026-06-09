use super::Result;
use crate::RecursiveError;

impl super::Conversation {
    /// Generate a new [`crate::HistorySecret`].
    ///
    /// This is useful when it's this client's turn to generate a new history client.
    ///
    /// The generated secret is cryptographically unrelated to the current CoreCrypto client.
    pub async fn generate_history_secret(&self) -> Result<crate::HistorySecret> {
        crate::ephemeral::generate_history_secret(self.configuration.cipher_suite)
            .await
            .map_err(RecursiveError::root("generating history secret"))
            .map_err(Into::into)
    }

    /// Check if history sharing is enabled, i.e., if any of the conversation members have a [ClientId][crate::ClientId]
    /// starting with [crate::HISTORY_CLIENT_ID_PREFIX].
    pub async fn is_history_sharing_enabled(&self) -> bool {
        !self.get_history_client_ids().await.is_empty()
    }
}
