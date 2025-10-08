use super::Result;
use crate::{Credential, RecursiveError, Session, mls::credential::FindFilters};

impl Session {
    /// Find all credentials which match the specified conditions.
    ///
    /// If no filters are set, this is equivalent to [`get_credentials`][Self::get_credentials].
    ///
    /// This is a convenience method entirely equivaleent to [Credential::find];
    /// the only difference is that it automatically includes the appropriate
    /// [`Database`][core_crypto_keystore::Databsae] reference.
    pub async fn find_credentials(&self, find_filters: FindFilters<'_>) -> Result<Vec<Credential>> {
        let database = self.crypto_provider.keystore();
        Credential::find(&database, find_filters)
            .await
            .map_err(RecursiveError::mls_credential("finding credentials"))
            .map_err(Into::into)
    }

    /// Get all credentials
    ///
    /// This is a convenience method entirely equivaleent to [Credential::get_all];
    /// the only difference is that it automatically includes the appropriate
    /// [`Database`][core_crypto_keystore::Databsae] reference.
    pub async fn get_credentials(&self) -> Result<Vec<Credential>> {
        let database = self.crypto_provider.keystore();
        Credential::get_all(&database)
            .await
            .map_err(RecursiveError::mls_credential("getting all credentials"))
            .map_err(Into::into)
    }
}
