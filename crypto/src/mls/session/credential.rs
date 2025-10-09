use super::Result;
use crate::{CredentialRef, FindFilters, RecursiveError, Session};

impl Session {
    /// Find all credentials which match the specified conditions.
    ///
    /// If no filters are set, this is equivalent to [`get_credentials`][Self::get_credentials].
    ///
    /// This is a convenience method entirely equivalent to [CredentialRef::find];
    /// the only difference is that it automatically includes the appropriate
    /// [`Database`][core_crypto_keystore::Database] reference.
    pub async fn find_credentials(&self, find_filters: FindFilters<'_>) -> Result<Vec<CredentialRef>> {
        let database = self.crypto_provider.keystore();
        CredentialRef::find(&database, find_filters)
            .await
            .map_err(RecursiveError::mls_credential_ref("finding credentials"))
            .map_err(Into::into)
    }

    /// Get all credentials
    ///
    /// This is a convenience method entirely equivalent to [CredentialRef::get_all];
    /// the only difference is that it automatically includes the appropriate
    /// [`Database`][core_crypto_keystore::Database] reference.
    pub async fn get_credentials(&self) -> Result<Vec<CredentialRef>> {
        let database = self.crypto_provider.keystore();
        CredentialRef::get_all(&database)
            .await
            .map_err(RecursiveError::mls_credential_ref("getting all credentials"))
            .map_err(Into::into)
    }
}
