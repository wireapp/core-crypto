use super::Result;
use crate::{RecursiveError, ephemeral::is_history_client};

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
    /// ending with [crate::HISTORY_CLIENT_ID_SUFFIX].
    pub async fn is_history_sharing_enabled(&self) -> Result<bool> {
        self.get_client_ids()
            .await
            .map(|client_ids| client_ids.iter().any(|client_id| is_history_client(client_id)))
    }
}
