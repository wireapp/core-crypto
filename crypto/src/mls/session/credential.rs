use std::sync::Arc;

use core_crypto_keystore::traits::FetchFromDatabase;
use openmls::prelude::SignaturePublicKey;

use super::Result;
use crate::{Credential, CredentialFindFilters, CredentialRef, RecursiveError, Session};

impl<D> Session<D> {
    /// Find all credentials known by this session which match the specified conditions.
    ///
    /// If no filters are set, this is equivalent to [`Self::get_credentials`].
    pub async fn find_credentials(&self, find_filters: CredentialFindFilters<'_>) -> Result<Vec<CredentialRef>>
    where
        D: FetchFromDatabase,
    {
        CredentialRef::find(self.database(), find_filters)
            .await
            .map_err(RecursiveError::mls_credential_ref("finding credentials with filters"))
            .map_err(Into::into)
    }

    /// Get all credentials known by this session.
    pub async fn get_credentials(&self) -> Result<Vec<CredentialRef>>
    where
        D: FetchFromDatabase,
    {
        self.find_credentials(Default::default()).await
    }

    /// convenience function deferring to the implementation on the inner type
    pub(crate) async fn find_credential_by_public_key(&self, public_key: &SignaturePublicKey) -> Result<Arc<Credential>>
    where
        D: FetchFromDatabase,
    {
        let credential = Credential::find_by_public_key(&self.database, public_key)
            .await
            .map_err(RecursiveError::mls_credential("getting credential by public key"))?;
        Ok(Arc::new(credential))
    }
}
